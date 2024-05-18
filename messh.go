package main

import (
	"strings"
	"os"
	"fmt"
	"time"
	"sort"
	"strconv"
	"context"
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
	addr	string
	port	int
	user	string
	labels	[]string
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

type stats struct {
	Ok		int
	Err		int
	Total	int
	Avg		time.Duration
	Min		time.Duration
	Max		time.Duration
	Time	time.Duration
}

var global struct {
	config		Config
	hosts		[]host
	results		[]result
	start		time.Time
	pool		*gpool.Pool
	progress	*pterm.ProgressbarPrinter
	outputCEL	cel.Program
	filterCEL	cel.Program
}

type Config struct {
	Parallelism int				`arg:"-p" default:"1" help:"max number of parallel connection"`
	Hosts		string			`arg:"-f,required"`
	Template	string			`arg:"-t" default:"{host} {tag} {out}" help:"Output template"`
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
	return "MeSSH 0.3.0"
}

func getCEL(expr string, env *cel.Env) cel.Program {
	if env == nil {
		newenv, err := cel.NewEnv(
			ext.Math(),
			ext.Strings(),
			cel.Variable("Host",		cel.StringType),
			cel.Variable("Out",			cel.StringType),
			cel.Variable("Tag",			cel.StringType),
			cel.Variable("Time",		types.DurationType),
			cel.Variable("CommandErr",	cel.StringType),
			cel.Variable("UploadErr",	cel.StringType),
			cel.Variable("DownloadErr",	cel.StringType),
			cel.Variable("Stats",		cel.MapType(cel.StringType, cel.AnyType)),
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
		if (len(fields) < 1) {
			continue
		} else if (len(fields) > 2) {
			panic("broken record in hosts file")
		} else if (len(fields) > 1) {
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
		hosts = append(hosts, host{addr: hst, user: user, port: port, labels: labels})
	}
	return hosts
}

func header () {
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

func summary (results []result, stats stats) {
	pterm.DefaultSection.Println("Session summary")
	pterm.Println(pterm.Yellow("* Date                  :"), pterm.Cyan(time.Now()))
	pterm.Println(pterm.Yellow("* Total runtime         :"), pterm.Cyan(time.Now().Sub(global.start)))
	pterm.Println(pterm.Yellow("* Total runtime         :"), pterm.Cyan(stats.Time))
	pterm.Println(pterm.Yellow("* Avg(t) per host       :"), pterm.Cyan(stats.Avg))
	pterm.Println(pterm.Yellow("* Min(t) per host       :"), pterm.Cyan(stats.Min))
	pterm.Println(pterm.Yellow("* Max(t) per host       :"), pterm.Cyan(stats.Min))
	pterm.Println(pterm.Yellow("* Total results         :"), pterm.Cyan(len(results)))
	pterm.Println(pterm.Yellow("* Successful            :"), pterm.Cyan(stats.Ok))
	pterm.Println(pterm.Yellow("* Failed                :"), pterm.Cyan(stats.Err))
}

func filterOne (res result, stats stats) bool {
	filtmap := make(map[string]any)
	if err := mapstructure.WeakDecode(res, &filtmap); err != nil {
		panic(err)
	}
	statmap := make(map[string]any)
	if err := mapstructure.WeakDecode(stats, &statmap); err != nil {
		panic(err)
	}
	filtmap["Stats"] = statmap

	val, _, err := global.filterCEL.Eval(filtmap)
	if err != nil {
		panic(err)
	}
	return val == types.True
}

func filterResults (results []result, stats stats) (filtered []result) {
	for _, res := range results {
		if filterOne(res, stats) {
			filtered = append(filtered, res)
		}
	}	
	return
}

func sortResults (results []result) {
	celenv, _ := cel.NewEnv(
		cel.Variable("a", cel.MapType(cel.StringType, cel.AnyType)),
		cel.Variable("b", cel.MapType(cel.StringType, cel.AnyType)),
	)
	sortCEL := getCEL(global.config.Sort, celenv)
	sort.Slice(results, func(i, j int) bool {
		sortmap := make(map[string]any)
		sortmap["a"] = *results[i].as_map
		sortmap["b"] = *results[j].as_map
		val, _, _ := sortCEL.Eval(sortmap)
		return val == types.True
	})
}

func sortR (results []result, field string) []result {
	//sorter := getCEL(global.config.Sort, nil)
	sort.Slice(results, func(i, j int) bool {
		switch field {
		case "time":
			return results[i].Time > results[j].Time
		case "host":
			return results[i].Host > results[j].Host
/*
		case "status":
			return results[i].status > results[j].status
*/
		default:
			return false
		}
	})
	return results
}

func resultExtras (res *result) {
	
}

func output (res result) {
	if global.config.Template == "" {
		return
	}
	fields := map[string]interface{}{
		"host":		fmt.Sprintf("%32s", res.Host),
		"time":		res.Time.String(),
		"out":		strings.TrimSuffix(res.Out, "\n"),
		"status":	"OK",
		"tag":		color.GreenString("->"),
	}
	if res.Cmd != nil {
		fields["status"] = "ERR"
		fields["tag"] = color.RedString("=:")
	}
//	pterm.Println(fasttemplate.New(global.config.Template, "{", "}").ExecuteString(fields))
	wut, _, err := global.outputCEL.Eval(*res.as_map)
	if err != nil {
		panic(err)
	}
	pterm.Println(wut.ConvertToType(cel.StringType))
}

func outp (res result) {
	wut, _, _ := global.outputCEL.Eval(res.as_map)
	wut.ConvertToType(cel.StringType)
}

func render (res result, results []result) {
	stats := getStats(results)
	global.progress.UpdateTitle(fmt.Sprintf("%d/%d conns, %d OK, %d ERR, %s avg",
					global.pool.GetCurrent(), global.pool.GetSize(), stats.Ok, stats.Err, stats.Avg))
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
	res := result{Host: host.addr}

	auth := getAuth()()
	cb, _ := goph.DefaultKnownHosts()
	ssh, err := goph.NewConn(&goph.Config{Auth: auth, User: host.user, Addr: host.addr, Port: uint(host.port), Callback: cb})
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

func getStats (results []result) stats {
	stats := stats{}
	var spent time.Duration
	for _, res := range results {
		if res.Cmd == nil {
			stats.Ok++
		} else {
			stats.Err++
		}
		if res.Time < stats.Min {
			stats.Min = res.Time
		} else if res.Time > stats.Max {
			stats.Max = res.Time
		}
		spent += res.Time
	}
	stats.Total = stats.Ok + stats.Err
	if len(results) > 0 {
		stats.Avg = spent / time.Duration(len(results))
	}
	stats.Time = time.Now().Sub(global.start)
	return stats
}

func dial (job job) []result {
	var results []result
	global.pool = gpool.NewPool(global.config.Parallelism)
	for _, host := range global.hosts {
		host := host
		global.pool.Enqueue(context.Background(), func() {
			time.Sleep(global.config.Delay)
			result := execute(host, job)
			output(result)
			results = append(results, result)
			render(result, results)
		})
	}
	global.pool.Stop()

	return results
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
//	hosts := prepareHosts()
//	os.Exit(0)

	global.progress, _ = pterm.DefaultProgressbar.WithTotal(len(global.hosts)).WithTitle("Mess SSH").WithMaxWidth(120).Start()

	results := dial(job{cmd: append([]string{global.config.Command}, global.config.Args...)})
//	results = global.results

fmt.Println(results)
	stats := getStats(results)
	results = filterResults(results, stats)
// save(results) // sqlite
	sortResults(results)
// output(results, stats) // file(s)
// display(results, stats)
/*	for _, res = range results {
		printRes(res)
	}
*/
	summary(results, stats)
}

func main () {
	global.start = time.Now()

	arg.MustParse(&global.config)
	global.hosts = parseHosts(global.config.Hosts)

	global.outputCEL = getCEL(global.config.Template, nil)
	global.filterCEL = getCEL(global.config.Filter, nil)

	go kbd()
	messh()
}
