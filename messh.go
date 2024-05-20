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
//	"github.com/rivo/tview"
	"github.com/sherifabdlnaby/gpool"
_	"github.com/davecgh/go-spew/spew"
	"github.com/melbahja/goph"
_	"golang.org/x/crypto/ssh"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/eiannone/keyboard"
	"github.com/alexflint/go-arg"

//	"github.com/valyala/fasttemplate"

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
	as_map		*map[string]interface{}
}

type session struct {
	Ok		int
	Err		int
	Total	int
	Avg		time.Duration
	Min		time.Duration
	Max		time.Duration
	Time	time.Duration
}

type stats struct {

}

var global struct {
	config		Config
	hosts		[]host
	results		[]result
	start		time.Time
	pool		*gpool.Pool
	progress	*pterm.ProgressbarPrinter
	formatCEL	cel.Program
	filterCEL	cel.Program
}

type Config struct {
	Bare		bool			`arg:"-b" help:"don't print extra headers or summary"`
	Parallelism int				`arg:"-p" default:"1" help:"max number of parallel connection"`
	Hosts		string			`arg:"-f,required"`
	Template	string			`arg:"-t" default:"{host} {tag} {out}" help:"Format template"`
	Output		string			`arg:"-o" default:"{host} {tag} {out}" help:"Output template"`
	Order		string			`arg:"-O" help:"Order hosts before execution"`
	Filter		string			`arg:"-F" help:"CEL expression to filter out unwanted entries"`
	Immediate	bool			`arg:"-i" default:"true" help:"Print output immediately without waiting for all hosts to complete"`
	Delay		time.Duration	`arg:"-d" default:"10ms" help:"Delay each new connection by specified time, to avoid congestion"`
	Labels		[]string		`arg:"-l" placeholder:"LABEL..." help:"Execute command only on hosts having the specified labels"`			
	Group		[]string		`arg:"-g" placeholder:"FIELD|LABEL..." help:"Group connections by the specified fields or labels"`
	Upload		[]string		`arg:"-U" placeholder:"LOCAL [REMOTE]"`
	Download	string			`arg:"-D" placeholder:"REMOTE [LOCAL]"`
	Sort		string			`arg:"-s"`
	Command		string			`arg:"positional" help:"Command to run"`
	Args		[]string		`arg:"positional" help:"Any command line arguments"`
}

func (Config) Version() string {
	return "MeSSH 0.5.0"
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

func parseHosts (path string) []host {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var hosts []host
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		var port int
		var user, hst string
		var labels []string
		fields := strings.Fields(line)
		if len(fields) < 1 || strings.HasPrefix(line, "#") {
			continue
		} else if len(fields) > 2 {
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
		hosts = append(hosts, host{Addr: hst, User: user, Port: port, Labels: labels})
	}
	return hosts
}

func header () {
	if global.config.Bare {
		return
	}
	logo, _ := pterm.DefaultBigText.WithLetters(putils.LettersFromStringWithStyle(global.config.Version(), pterm.FgYellow.ToStyle())).Srender()
	pterm.Println(logo)
	pterm.DefaultSection.Println("Session parameters")
	pterm.Println(pterm.Yellow("* Date              	:"), pterm.Cyan(time.Now()))
	pterm.Println(pterm.Yellow("* Hosts file        	:"), pterm.Cyan(global.config.Hosts))
	pterm.Println(pterm.Yellow("* Hosts count       	:"), pterm.Cyan(len(global.hosts)))
	pterm.Println(pterm.Yellow("* Parallel instances	:"), pterm.Cyan(global.config.Parallelism))
	pterm.Println(pterm.Yellow("* Delay             	:"), pterm.Cyan(global.config.Delay))
	pterm.Println(pterm.Yellow("* Command            	:"), pterm.Cyan(global.config.Command))
	pterm.Println(pterm.Yellow("* Args              	:"), pterm.Cyan(global.config.Args))

	pterm.DefaultSection.Println("Running command ...")
}

func summary (results []result, session session) {
	if global.config.Bare {
		return
	}
	pterm.DefaultSection.Println("Session summary")
	pterm.Println(pterm.Yellow("* Date                  :"), pterm.Cyan(time.Now()))
	pterm.Println(pterm.Yellow("* Total runtime         :"), pterm.Cyan(time.Now().Sub(global.start)))
	pterm.Println(pterm.Yellow("* Total runtime         :"), pterm.Cyan(session.Time))
	pterm.Println(pterm.Yellow("* Avg(t) per host       :"), pterm.Cyan(session.Avg))
	pterm.Println(pterm.Yellow("* Min(t) per host       :"), pterm.Cyan(session.Min))
	pterm.Println(pterm.Yellow("* Max(t) per host       :"), pterm.Cyan(session.Min))
	pterm.Println(pterm.Yellow("* Total results         :"), pterm.Cyan(len(results)))
	pterm.Println(pterm.Yellow("* Successful            :"), pterm.Cyan(session.Ok))
	pterm.Println(pterm.Yellow("* Failed                :"), pterm.Cyan(session.Err))
}

func order [T any] (expr string, list []T) {
	orderCEL := getCEL(expr, nil)
	sort.Slice(list, func(i, j int) bool {
		return evalCEL(orderCEL, reflect.TypeOf(true), []any{}, map[string]any{
			"a": list[i],
			"b": list[j],
		}).(bool)
	})
}

func filterResults (results []result, session session) (filtered []result) {
	for _, res := range results {
		if evalCEL(global.filterCEL, reflect.TypeOf(true), []any{res}, map[string]any{"Session": session, "Config": global.config}).(bool) {
			filtered = append(filtered, res)
		}
	}	
	return
}

func formatRes (res result, prg cel.Program) string {
	extra := map[string]interface{}{
		"Host32":	fmt.Sprintf("%32s", res.Host),
		"Status":	"OK",
		"Arrow"	:	color.GreenString("->"),
	}
	if res.Cmd != nil {
		extra["Status"] = "ERR"
		extra["Arrow"] = color.RedString("=:")
	}
	for k, v := range *res.as_map {
		extra[k] = v
	}

	line :=	evalCEL(prg, reflect.TypeOf("String"), []any{extra}, map[string]any{})
	return line.(string)
}

func printRes (res result) {
	if global.config.Template == "" {
		return
	}

	pterm.Println(formatRes(res, global.formatCEL))
}

func render (res result, results []result) {
	session := getStats(results)
	if global.config.Immediate {
		printRes(res)
	}
	global.progress.UpdateTitle(fmt.Sprintf("%d/%d conns, %d OK, %d ERR, %s avg",
					global.pool.GetCurrent(), global.pool.GetSize(), session.Ok, session.Err, session.Avg))
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
	if err := mapstructure.WeakDecode(res, &res.as_map); err != nil {
		panic(err)
	}

	return res
}

func getStats (results []result) session {
	session := session{}
	var spent time.Duration
	for _, res := range results {
		if res.Cmd == nil {
			session.Ok++
		} else {
			session.Err++
		}
		if res.Time < session.Min {
			session.Min = res.Time
		} else if res.Time > session.Max {
			session.Max = res.Time
		}
		spent += res.Time
	}
	session.Total = session.Ok + session.Err
	if len(results) > 0 {
		session.Avg = spent / time.Duration(len(results))
	}
	session.Time = time.Now().Sub(global.start)
	return session
}

func dial (job job) []result {
	var results []result
	global.pool = gpool.NewPool(global.config.Parallelism)
	for _, host := range global.hosts {
		host := host
		global.pool.Enqueue(context.Background(), func() {
			time.Sleep(global.config.Delay)
			result := execute(host, job)
			results = append(results, result)
			render(result, results)
		})
	}
	global.pool.Stop()

	return results
}

func output (results []result) {
	if global.config.Output == "" || global.config.Template == "" {
		return
	}
	files := make(map[string][]string)
	prog := getCEL(global.config.Output, nil)
	for _, res := range results {
		val := evalCEL(prog, reflect.TypeOf("string"), []any{res}, map[string]any{"Config": global.config})
		path := val.(string)
		files[path] = append(files[path], formatRes(res, global.formatCEL))
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
		fmt.Printf("You pressed: rune %q, key %X\r\n", char, key)
		if key == keyboard.KeyCtrlC {
			os.Exit(0)

			global.pool.Stop()
			pterm.DefaultInteractiveConfirm.WithDefaultText("Abort?").Show()
			time.Sleep(30 * time.Second)
		} else if key == keyboard.KeySpace {
			global.progress.UpdateTitle("[PAUSED] " + global.progress.Title)
//			global.progress.Stop()
			global.pool.Stop()
		} else if key == keyboard.KeyEnter {
//			global.progress.Start()
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

func messh () {
	header()
	global.progress, _ = pterm.DefaultProgressbar.WithTotal(len(global.hosts)).WithTitle("Mess SSH").WithMaxWidth(120).Start()

	results := dial(job{cmd: append([]string{global.config.Command}, global.config.Args...)})
	session := getStats(results)
	results = filterResults(results, session)
// save(results) // sqlite
	order(global.config.Sort, results)
	output(results)
// output(results, session) // file(s)
	if ! global.config.Immediate {
		for _, res := range results {
			printRes(res)
		}
	}
	summary(results, session)
}

func main () {
	global.start = time.Now()

	arg.MustParse(&global.config)
	global.hosts = parseHosts(global.config.Hosts)
	order(global.config.Order, global.hosts)

	global.formatCEL = getCEL(global.config.Template, nil)
	global.filterCEL = getCEL(global.config.Filter, nil)

	go kbd()
	messh()
}
