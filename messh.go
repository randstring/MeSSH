package main

import (
	"strings"
	"os"
	"fmt"
	"time"
	"sort"
	"strconv"
	"context"
	"reflect"
	"path/filepath"
	"github.com/fatih/color"
	"github.com/sherifabdlnaby/gpool"
_	"github.com/davecgh/go-spew/spew"
	"github.com/melbahja/goph"
_	"golang.org/x/crypto/ssh"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/eiannone/keyboard"
	"github.com/alecthomas/kong"
	"github.com/alecthomas/kong-hcl"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/mitchellh/mapstructure"
)

type host struct {
	Addr	string
	Port	int
	User	string
	Labels	[]string
}

type Transfer struct {
	from	string
	to		string
}

type job struct {
	cmd			[]string
	combined	bool
	download	*Transfer
	upload		*Transfer
}

type result struct {
	Host		string
//	exit		int
//	stdout		string
//	stderr		string
	Out			string
	Cmd			error
	Upload		error
	Download	error
	Time		time.Duration
}

type session struct {
	Ok			int
	Err			int
	Count		int
	Avg			time.Duration
	Min			time.Duration
	Max			time.Duration
	Total		time.Duration
	Duration	time.Duration
}

type stats struct {

}

var global struct {
	config		Config
	stats		stats
	session		session
	hosts		[]host
	results		[]result
	start		time.Time
	pool		*gpool.Pool
	progress	*pterm.ProgressbarPrinter
	paused		bool
	version		string "0.6.1"
}

type Config struct {
	Bare			bool			`short:"b" negatable help:"bare output; don't print extra headers or summary"`
	Config			kong.ConfigFlag	`short:"c" help:"load configuration from file"`
	Delay			time.Duration	`short:"d" default:"10ms" help:"delay each new connection by the specified time, avoiding congestion"`
	Timeout			time.Duration	`short:"t" default:"30s" help:"connection timeout"`
	Parallelism		int				`short:"m" aliases:"max" default:1 help:"max number of parallel connections"`
	Hosts			struct {
		File		[]byte			`short:"f" aliases:"read" required type:"filecontent" help:"hosts file"`
		Filter		string			`placeholder:"EXPR(host)bool" help:"hosts filter expression"`
		Order		string			`placeholder:"EXPR(a,b)bool" help:"hosts ordering expression"`
	}								`embed prefix:"hosts-"`
	Print			struct {
		Template	string			`short:"p" placeholder:"EXPR(host)string" help:"hosts filter expression"`
		Order		string			`placeholder:"EXPR(a,b)bool" help:"print ordering expression"`
	}								`embed prefix:"print-"`
	Log				struct {
		File		string			`short:"l" placeholder:"EXPR(res)string" help:"string expression to generate log path"`
		Template	string			`placeholder:"EXPR(res)string" help:"string expression to generate log output"`		
		Order		string			`placeholder:"EXPR(a,b)bool" help:"log ordering expression"`
	}								`embed prefix:"log-"`
	Immed			string			`short:"i" aliases:"immediate" placeholder:"EXPR(res)string" help:"expression to print immediately for each result"`
	Script			string			`short:"x" type:"existingfile" help:"script to upload and run on each host"`
	Upload			struct	{
		From		string			`short:"U" type:"existingfile" placeholder:"LOCAL" help:"local file to upload"`
		To			string			`aliases:"ut" placeholder:"REMOTE" help:"remote file path for upload"`
	}								`embed prefix:"upload-"`
	Download		struct	{
		From		string			`short:"D" placeholder:"REMOTE" help:"remote file to download"`
		To			string			`aliases:"dt" placeholder:"EXPR(res)string" help:"local path expression to download files to"`
	}								`embed prefix:"download-"`
	Command			[]string		`arg optional help:"Command to run"`
	Version			kong.VersionFlag`short:"V" set:"version=0" help:"display version"`
}

func getCEL(expr string, env *cel.Env) cel.Program {
	if env == nil {
		newenv, err := cel.NewEnv(
			ext.Math(),
			ext.Strings(),
			cel.Variable("Config",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Session",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Stats",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("a",			cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("b",			cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Time",		types.DurationType),
			cel.Variable("Host",		cel.StringType),
			cel.Variable("Out",			cel.StringType),
			cel.Variable("Cmd",			cel.StringType),
			cel.Variable("Upload",		cel.StringType),
			cel.Variable("Download",	cel.StringType),
			cel.Variable("Host32",		cel.StringType),
			cel.Variable("Arrow",		cel.StringType),
			cel.Variable("Status",		cel.StringType),
		)
		if err != nil {
			panic(err)
		}
		env = newenv
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		panic(issues.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		panic(err)
	}
	return prg
}

func evalCEL (prog cel.Program, want reflect.Type, root []any, fields map[string]any) any {
	rootmap := make(map[string]any)
	for _, item := range root {
		if err := mapstructure.WeakDecode(item, &rootmap); err != nil {
			panic(err)
		}
	}
	for varname, st := range fields {
		fieldmap := make(map[string]any)
		if err := mapstructure.WeakDecode(st, &fieldmap); err != nil {
			panic(err)
		}
		rootmap[varname] = fieldmap
	}

	val, _, err := prog.Eval(rootmap)
	if err != nil {
		panic(err)
	}
	if result, err := val.ConvertToNative(want); err == nil {
		return result
	}
	panic("failed to convert expression to wanted type")
}

func parseHost (line string) host {
	var port int
	var user, hst string
	var labels []string
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) < 1 || len(fields) > 2 {
		panic("broken record in hosts file")
	} else if len(fields) > 1 {
		labels = strings.Split(fields[1], ",")
	}
	uhost := strings.Split(fields[0], "@")
	if len(uhost) > 1 {
		user, hst = uhost[0], uhost[1]
	} else {
		user = "root"
		hst = fields[0]
	}
	hostaddr := strings.Split(hst, ":")
	if len(hostaddr) > 1 {
		hst = hostaddr[0]
		port, _ = strconv.Atoi(hostaddr[1])
	} else {
		port = 22
	}
	return host{Addr: hst, User: user, Port: port, Labels: labels}
}

func prepareHosts (content []byte) []host {
	var hosts []host
	var filter cel.Program
 	if global.config.Hosts.Filter != "" {
		filter = getCEL(global.config.Hosts.Filter, nil)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		hostent := parseHost(line)
		if filter == nil || evalCEL(filter, reflect.TypeOf(true), []any{hostent}, map[string]any{}).(bool) {
			hosts = append(hosts, hostent)
		}
	}

	if global.config.Hosts.Order != "" {
		order(global.config.Hosts.Order, hosts)
	}
	return hosts
}

func header () {
	if global.config.Bare {
		return
	}
	logo, _ := pterm.DefaultBigText.WithLetters(putils.LettersFromStringWithStyle(global.version, pterm.FgYellow.ToStyle())).Srender()
	pterm.Println(logo)
	pterm.DefaultSection.Println("Session parameters")
	pterm.Println(pterm.Yellow("* Date              	:"), pterm.Cyan(time.Now()))
	pterm.Println(pterm.Yellow("* Hosts file        	:"), pterm.Cyan(global.config.Hosts))
	pterm.Println(pterm.Yellow("* Hosts count       	:"), pterm.Cyan(len(global.hosts)))
	pterm.Println(pterm.Yellow("* Parallel instances	:"), pterm.Cyan(global.config.Parallelism))
	pterm.Println(pterm.Yellow("* Delay             	:"), pterm.Cyan(global.config.Delay))
	pterm.Println(pterm.Yellow("* Command            	:"), pterm.Cyan(global.config.Command))
	pterm.Println(pterm.Yellow("* Connect timeout       :"), pterm.Cyan(global.config.Timeout))

	pterm.DefaultSection.Println("Running command ...")
}

func summary (results []result) {
	if global.config.Bare {
		return
	}
	pterm.DefaultSection.Println("Session summary")
	pterm.Println(pterm.Yellow("* Date                  :"), pterm.Cyan(time.Now()))
	pterm.Println(pterm.Yellow("* Total runtime         :"), pterm.Cyan(global.session.Total))
	pterm.Println(pterm.Yellow("* Avg(t) per host       :"), pterm.Cyan(global.session.Avg))
	pterm.Println(pterm.Yellow("* Min(t) per host       :"), pterm.Cyan(global.session.Min))
	pterm.Println(pterm.Yellow("* Max(t) per host       :"), pterm.Cyan(global.session.Max))
	pterm.Println(pterm.Yellow("* Total results         :"), pterm.Cyan(len(results)))
	pterm.Println(pterm.Yellow("* Successful            :"), pterm.Cyan(global.session.Ok))
	pterm.Println(pterm.Yellow("* Failed                :"), pterm.Cyan(global.session.Err))
}

func order [T any] (expr string, list []T) {
	orderCEL := getCEL(expr, nil)
	sort.Slice(list, func(i, j int) bool {
		return evalCEL(orderCEL, reflect.TypeOf(true), []any{}, map[string]any{
			"a": list[i],
			"b": list[j],
			"Config": global.config,
		}).(bool)
	})
}

func formatRes (res result, prog cel.Program) string {
	extra := map[string]any{
		"Host32":	fmt.Sprintf("%32s", res.Host),
		"Status":	"OK",
		"Arrow"	:	color.GreenString("->"),
	}
	if res.Cmd != nil {
		extra["Status"] = "ERR"
		extra["Arrow"] = color.RedString("=:")
	}

	line :=	evalCEL(prog, reflect.TypeOf("String"), []any{res, extra}, map[string]any{})
	return line.(string)
}

func printRes (res result, prog cel.Program) {
	line := formatRes(res, prog)
	if line != "" {
		pterm.Println(line)
	}
}

func display(results []result) {
	if global.config.Print.Order != "" {
		order(global.config.Print.Order, results)
	}
	if global.config.Print.Template != "" {
		prog := getCEL(global.config.Print.Template, nil)
		for _, res := range results {
			printRes(res, prog)
		}
	}
}

func render (res result, prog cel.Program) {
	updateStats(res)
	if prog != nil {
		printRes(res, prog)
	}
	global.progress.UpdateTitle(fmt.Sprintf("%d/%d conns, %d OK, %d ERR, %s avg",
					global.pool.GetCurrent(), global.pool.GetSize(), global.session.Ok, global.session.Err, global.session.Avg))
	global.progress.Increment()
}

func getAuth () func () goph.Auth {
	var auth *goph.Auth

	return func() goph.Auth {
		if auth != nil {
			return *auth
		}

		newauth, err := goph.Key("/home/dimitral/.ssh/rsa", "")
		if err != nil {
			panic(err)
		}
		auth = &newauth
		return newauth
	}
}

func execute (host host, job job) (result) {
	start := time.Now()
	res := result{Host: host.Addr}

	auth := getAuth()()
	cb, _ := goph.DefaultKnownHosts()
	ssh, err := goph.NewConn(&goph.Config{Auth: auth, User: host.User, Addr: host.Addr, Port: uint(host.Port), Callback: cb})
	if err != nil {
		fmt.Println(err)
		return res
	}

	// any uploads go first
	if job.upload != nil {
		res.Upload = ssh.Upload(job.upload.from, job.upload.to)
	}
	if len(job.cmd) > 0 {
		cmd, err := ssh.Command(job.cmd[0], job.cmd[1:]...)
		if err != nil {
			res.Cmd = err
		} else {
			if job.combined {
				out, err := cmd.CombinedOutput()
				res.Out = strings.TrimSuffix(string(out), "\n")
				res.Cmd = err
			} else {
				out, err := cmd.CombinedOutput()
				res.Out = strings.TrimSuffix(string(out), "\n")
				res.Cmd = err
			}
		}
	}
	// downloads go last
	if job.download != nil {
		res.Download = ssh.Download(job.download.from, job.download.to)
	}

	end := time.Now()
	res.Time = end.Sub(start)

	return res
}

func updateStats (res result) {
	global.session.Count++
	if res.Cmd == nil {
		global.session.Ok++
	} else {
		global.session.Err++
	}
	if res.Time < global.session.Min {
		global.session.Min = res.Time
	} else if res.Time > global.session.Max {
		global.session.Max = res.Time
	}
	global.session.Total += res.Time
	global.session.Avg = global.session.Total / time.Duration(global.session.Count)
	global.session.Duration = time.Now().Sub(global.start)
}

func dial (job job) []result {
	var results []result
	var prog cel.Program
	if global.config.Immed != "" {
		prog = getCEL(global.config.Immed, nil)
	}
	global.pool = gpool.NewPool(global.config.Parallelism)
	for _, host := range global.hosts {
		host := host
		global.pool.Enqueue(context.Background(), func() {
			time.Sleep(global.config.Delay)
			result := execute(host, job)
			render(result, prog)
			results = append(results, result)
		})
	}
	global.pool.Stop()

	return results
}

func output (results []result) {
	if global.config.Log.File == "" || global.config.Log.Template == "" {
		return
	} else if global.config.Log.Order != "" {
		order(global.config.Log.Order, results)
	}
	files := make(map[string][]string)
	fileprog := getCEL(global.config.Log.File, nil)
	filtprog := getCEL(global.config.Log.Template, nil)
	for _, res := range results {
		val := evalCEL(fileprog, reflect.TypeOf("string"), []any{res}, map[string]any{"Config": global.config})
		path := val.(string)
		files[path] = append(files[path], formatRes(res, filtprog))
	}
	for file, lines := range files {
		dir := filepath.Dir(file)
		err := os.MkdirAll(dir, 0750)
		if err != nil {
			fmt.Println(err)
			continue
		}
		err = os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0660)
		if err != nil {
			fmt.Println(err)
		}
	}
}

func kbd () {
	if err := keyboard.Open(); err != nil {
		panic(err)
	}
	for {
		char, key, err := keyboard.GetKey()
		if err != nil {
			panic(err)
		}
//		fmt.Printf("You pressed: rune %q, key %X\r\n", char, key)
		if key == keyboard.KeyCtrlC {
			os.Exit(0)

			global.pool.Stop()
			pterm.DefaultInteractiveConfirm.WithDefaultText("Abort?").Show()
			time.Sleep(30 * time.Second)
		} else if key == keyboard.KeySpace && !global.paused {
			global.paused = true
			global.progress.UpdateTitle("[PAUSED] " + global.progress.Title)
			global.progress.Stop()
			global.pool.Stop()
		} else if key == keyboard.KeyEnter && global.paused {
			global.paused = false
			global.progress.UpdateTitle(strings.TrimPrefix(global.progress.Title, "[PAUSED] "))
			global.progress.Start()
			global.pool.Start()
		} else if char == '+' {
			fmt.Println("Size is", global.pool.GetSize())
			global.pool.Resize(global.pool.GetSize() + 1)
		} else if char == '-' {
			cur := global.pool.GetSize()
			if cur > 1 {
				global.pool.Resize(cur - 1)
			}
			fmt.Println("Size is", global.pool.GetSize())
		}
	}
}

func main () {
	global.start = time.Now()
	kong.Parse(&global.config, kong.Vars{"version": global.version}, kong.Configuration(konghcl.Loader, "messh.conf"))

	global.hosts = prepareHosts(global.config.Hosts.File)

	go kbd()
	header()
	global.progress, _ = pterm.DefaultProgressbar.WithTotal(len(global.hosts)).WithTitle("Mess SSH").WithMaxWidth(120).Start()
	results := dial(job{cmd: global.config.Command})
// save(results) // sqlite
	display(results)
	output(results)
	summary(results)
}
