package main

import (
	"strings"
	"os"
	"io"
	"net"
	"fmt"
	"time"
	"sort"
	"sync"
	"bytes"
	"regexp"
	"errors"
	"context"
	"reflect"
	"path/filepath"
	"github.com/fatih/color"
	"github.com/sherifabdlnaby/gpool"
_	"github.com/davecgh/go-spew/spew"
	"github.com/kevinburke/ssh_config"
	"github.com/melbahja/goph"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"github.com/pkg/sftp"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/eiannone/keyboard"
	"github.com/alecthomas/kong"
	"github.com/alecthomas/kong-hcl"

	"github.com/thanhpk/randstr"
	"github.com/jychri/tilde"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/mitchellh/mapstructure"

	"github.com/alessio/shellescape"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"github.com/glebarez/sqlite"
//	"gorm.io/driver/sqlite"

_	"runtime/pprof"
)

const (
	version = "MeSSH 0.8.5"
)

var config = []string {"messh.conf", "~/.messh.conf"}

type host struct {
	Alias	string
	Addr	string
	Port	string
	Labels	[]string
	SSH		ssh.ClientConfig
	Stats	HostStats
}

type Transfer struct {
	from	string
	to		string
	prog	cel.Program
}

type job struct {
	cmd			[]string
	script		string
	combined	bool
	download	*Transfer
	upload		*Transfer
}

type result struct {
	Alias		string
	Out			string
	Err			string
	Exit		int
	SSH			error
	Cmd			error
	Upload		error
	Download	error
	Host		host
	Time		time.Duration
}

type session struct {
	Ok			int
	Err			int
	Done		int
	Count		int
	Avg			time.Duration
	Min			time.Duration
	Max			time.Duration
	Total		time.Duration
	Duration	time.Duration
}

type HostData struct {
	gorm.Model
	Host		string `gorm:"index"`
	Out			string
	Failed		bool
	Time		time.Duration
	SessionID	uint
	Session		SessData
}

type SessData struct {
	gorm.Model
	Command		string
	Parallelism	uint
	Start		time.Time
	Duration	time.Duration
}

type HostStats struct {
	Count		int
	OK			int
	Err			int
	Period		float32 // takes part in each N sessions
	Avg			time.Duration
	Min			time.Duration
	Max			time.Duration
	Last		time.Duration
	Updated		time.Time
}

type SessStats struct {
	Count		int
	Command		string
	AvgHosts	float32
	Avg			time.Duration
	Min			time.Duration
	Max			time.Duration
	Last		time.Duration
	Period		time.Duration
	Updated		time.Time
}

var global struct {
	config		Config
	stats		SessStats
	session		session
	hosts		[]host
	results		[]result
	start		time.Time
	ssh_config	*ssh_config.Config
	pool		*gpool.Pool
	progress	*pterm.ProgressbarPrinter
	db			*gorm.DB
	sessdata	SessData
	paused		bool
	stopping	bool
	cancel		context.CancelFunc
	pause		sync.Mutex
	known_hosts	struct {
		strict	ssh.HostKeyCallback
		add		ssh.HostKeyCallback
		replace	ssh.HostKeyCallback
		ignore	ssh.HostKeyCallback
	}
	auth		struct {
		keyring		agent.Agent
		agent		ssh.AuthMethod
		keys		map[string]ssh.AuthMethod
	}
}

type Config struct {
	Bare			bool			`short:"b" negatable help:"bare output; don't print extra headers or summary"`
	Header			string			`short:"H" help:"custom header expression"`
	Summary			string			`short:"Z" help:"custom summary expression"`
	Config			kong.ConfigFlag	`short:"c" help:"load configuration from file"`
	Debug			bool			`short:"d" help:"enable debugging messages"`
	Database		string			`short:"E" default:"messh.db" help:"persist session data in a SQLite database at the specified location"`
	Delay			time.Duration	`short:"w" aliases:"wait" default:"10ms" help:"delay each new connection by the specified time, avoiding congestion"`
	Parallelism		uint			`short:"m" aliases:"max" default:1 help:"max number of parallel connections"`
	SSH				struct {
		Config		[]byte			`short:"C" type:"filecontent" default:"~/.ssh/config" help:"path to SSH config for host/auth configuration"`
		Opts		map[string]string`short:"O" placeholder:"OPT=VALUE,..." help:"any supported SSH config options, will override config values"`
	}								`embed prefix:"ssh-"`
	Hosts			struct {
		File		string			`short:"f" aliases:"read" xor:"hosts" required type:"existingfile" help:"hosts file"`
		Directive	string			`aliases:"hd" xor:"hosts" required help:"read hosts from ssh config, looking for the specified directive"`
		Filter		string			`aliaes:"hf" placeholder:"EXPR(host)bool" help:"hosts filter expression"`
		Order		string			`aliases:"ho" placeholder:"EXPR(a,b)bool" help:"hosts ordering expression"`
	}								`embed prefix:"hosts-"`
	Log				struct {
		File		string			`short:"l" placeholder:"EXPR(res)string" help:"string expression to generate log path"`
		Template	string			`short:"L" placeholder:"EXPR(res)string" help:"string expression to generate log output"`		
		Order		string			`aliases:"lo" placeholder:"EXPR(a,b)bool" help:"log ordering expression"`
	}								`embed prefix:"log-"`
	Print			struct {
		Immed		string			`short:"i" aliases:"immediate" placeholder:"EXPR(res)string" help:"expression to print immediately for each result"`
		Template	string			`short:"p" placeholder:"EXPR(host)string" help:"hosts filter expression"`
		Order		string			`aliases:"po" placeholder:"EXPR(a,b)bool" help:"print ordering expression"`
	}								`embed prefix:"print-"`
	Script			string			`short:"x" type:"existingfile" help:"script to upload and run on each host"`
	Upload			struct	{
		From		string			`short:"U" aliases:"uf" type:"existingfile" placeholder:"LOCAL" help:"local path expression to upload"`
		To			string			`aliases:"ut" placeholder:"REMOTE" help:"remote file path for upload"`
	}								`embed prefix:"upload-"`
	Download		struct	{
		From		string			`short:"D" aliases:"df" placeholder:"REMOTE" help:"remote file to download"`
		To			string			`aliases:"dt" placeholder:"EXPR(res)string" help:"local path expression to download files to"`
	}								`embed prefix:"download-"`
	Interleaved		bool			`short:"I" negatable default:"true" help:"interleave stdout and stderr in a single stream Out"`
	Command			[]string		`arg optional help:"Command to run"`
	Version			kong.VersionFlag`short:"V" set:"version=0" help:"display version"`
}


func order [T any] (expr string, list []T) {
	orderCEL := getCEL(expr, nil)
	sort.Slice(list, func(i, j int) bool {
		return evalCEL(orderCEL, reflect.TypeOf(true), []any{}, map[string]any{
			"a": list[i],
			"b": list[j],
			"Config": global.config,
			"Session": global.session,
			"Stats": global.stats,
		}).(bool)
	})
}

func getCEL(expr string, env *cel.Env) cel.Program {
	if env == nil {
		newenv, err := cel.NewEnv(
			ext.Math(),
			ext.Strings(),
			cel.Variable("Config",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Session",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Stats",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Host",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("a",			cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("b",			cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Labels",		cel.ListType(cel.StringType)),
			cel.Variable("Time",		types.DurationType),
			cel.Variable("Alias",		cel.StringType),
			cel.Variable("Out",			cel.StringType),
			cel.Variable("Err",			cel.StringType),
			cel.Variable("Cmd",			cel.StringType),
			cel.Variable("SSH",			cel.StringType),
			cel.Variable("Upload",		cel.StringType),
			cel.Variable("Download",	cel.StringType),
			cel.Variable("Arrow",		cel.StringType),
			cel.Variable("Status",		cel.StringType),
			cel.Variable("Addr",		cel.StringType),
			cel.Variable("Port",		cel.IntType),
			cel.Variable("Exit",		cel.IntType),
			cel.Function("ff",			cel.Overload("ff_string_list",
				[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
				cel.StringType,
				cel.BinaryBinding(func(left, right ref.Val) ref.Val {
					format, _ := left.ConvertToNative(reflect.TypeOf(""))
					lst, _ := right.ConvertToNative(reflect.TypeOf([]any{}))
					return types.String(fmt.Sprintf(format.(string), lst.([]any)...))
				}),
			)),
			cel.Function("f",			cel.Overload("f_list",
				[]*cel.Type{cel.ListType(cel.StringType)},
				cel.StringType,
				cel.UnaryBinding(func(left ref.Val) ref.Val {
					lst, _ := left.ConvertToNative(reflect.TypeOf([]any{}))
					return types.String(strings.TrimSuffix(fmt.Sprintln(lst.([]any)...), "\n"))
				}),
			)),
		)
		if err != nil {
			pterm.Fatal.Println(err)
		}
		env = newenv
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		pterm.Fatal.Println(issues.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		pterm.Fatal.Println(err)
	}
	return prg
}

func evalCEL (prog cel.Program, want reflect.Type, root []any, fields map[string]any) any {
	rootmap := make(map[string]any)
	for _, item := range root {
		if err := mapstructure.WeakDecode(item, &rootmap); err != nil {
			pterm.Fatal.Println(err)
		}
	}
	for varname, st := range fields {
		fieldmap := make(map[string]any)
		if err := mapstructure.WeakDecode(st, &fieldmap); err != nil {
			pterm.Fatal.Println(err)
		}
		rootmap[varname] = fieldmap
	}

//spew.Dump(rootmap["Host"])
	val, _, err := prog.Eval(rootmap)
	if err != nil {
		pterm.Fatal.Println(err)
	}
	if result, err := val.ConvertToNative(want); err == nil {
		return result
	}
	pterm.Fatal.Println("failed to convert CEL expression to wanted type")
	return nil
}

// Get a ssh_config value for the specified host with fallback to global or default values
func ssh_conf (alias string, key string) string {
	if val := global.config.SSH.Opts[key]; val != "" {
		return val
	} else if val, _ := global.ssh_config.Get(alias, key); val != "" {
		return val
	}
	return ssh_config.Default(key)
}

func hostkeyCB (hostname string, remote net.Addr, key ssh.PublicKey, replace bool) error {
	if global.known_hosts.strict == nil {
		return errors.New("No strict host checking callback.")
	}
	err := global.known_hosts.strict(hostname, remote, key)
	if err == nil {
		return nil
	}

	var keyErr *knownhosts.KeyError
	if !replace && errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
		return err
	}

	err = goph.AddKnownHost(hostname, remote, key, "")
	if (err != nil) {
		pterm.Warning.Println(err)
	}

	return nil
}

func initAuth() {
	global.known_hosts.ignore = ssh.InsecureIgnoreHostKey()
	global.known_hosts.add = func (hostname string, remote net.Addr, key ssh.PublicKey) error {
		return hostkeyCB(hostname, remote, key, false)
	}
	global.known_hosts.replace = func (hostname string, remote net.Addr, key ssh.PublicKey) error {
		return hostkeyCB(hostname, remote, key, true)
	}

	var known_hosts []string
	files := strings.Fields(ssh_conf("", "GlobalKnownHostsFile"))
	files = append(files, strings.Fields(ssh_conf("", "UserKnownHostsFile"))...)
	for _, file := range files {
		file = tilde.Abs(file)
		if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
			known_hosts = append(known_hosts, file)
		}
	}
	pterm.Debug.Println(known_hosts)
	strict, err := knownhosts.New(known_hosts...)
	if err != nil {
		pterm.Warning.Println(err)
	} else {
		global.known_hosts.strict = strict
	}
}

func hostAuthMethods (alias string) (auth []ssh.AuthMethod) {
	auth_order := strings.Split(ssh_conf(alias, "PreferredAuthentications"), ",")
	for _, method := range auth_order {
		switch method {
		case "publickey":
			if ssh_conf(alias, "PubkeyAuthentication") != "no" {
				keyfiles, _ := global.ssh_config.GetAll(alias, "IdentityFile")
				for _, file := range keyfiles {
					file = tilde.Abs(file)
					if _, ok := global.auth.keys[file]; !ok && global.auth.keys[file] == nil {
						if global.auth.keys == nil {
							global.auth.keys = make(map[string]ssh.AuthMethod)
						}
						global.auth.keys[file] = nil
						pk, err := os.ReadFile(file)
						if err != nil {
							pterm.Warning.Println(err)
							continue
						}				
						signer, err := ssh.ParsePrivateKey(pk)
						if _, ok := err.(*ssh.PassphraseMissingError); ok {
							pass, _ := pterm.DefaultInteractiveTextInput.WithMask("*").Show("Enter a password for ssh key "+file)
							signer, err = ssh.ParsePrivateKeyWithPassphrase(pk, []byte(pass))
						}
						if err == nil {
							global.auth.keys[file] = ssh.PublicKeys(signer)
						}
					}
					if global.auth.keys[file] != nil {
						auth = append(auth, global.auth.keys[file])
					}
				}
			}
			if ssh_conf(alias, "PubkeyAuthentication") != "no" && ssh_conf(alias, "IdentitiesOnly") != "yes" {
				if global.auth.agent == nil {
					if as, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
						global.auth.keyring = agent.NewClient(as)
						global.auth.agent = ssh.PublicKeysCallback(global.auth.keyring.Signers)
					}
				}
				if global.auth.agent != nil {
					auth = append(auth, global.auth.agent)
				}
			}
		case "keyboard-interactive":
			if ssh_conf(alias, "KbdInteractiveAuthentication") != "no" {
//				auth = append(auth, global.auth.kbi)
			}
		case "password":
			if ssh_conf(alias, "PasswordAuthentication") == "no" {
				break
			} else if pass := ssh_conf(alias, "Password"); pass != "" {
				auth = append(auth, ssh.Password(pass))
			}
		}
	}

	return
}

func hostConfig (line string) host {
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) < 1 {
		pterm.Fatal.Println("broken record in hosts file")
	}
	labels := fields[1:]
	alias := fields[0]
	addr := ssh_conf(alias, "HostName")
	if addr != "" {
		re := regexp.MustCompile(`%[%h]`)
		addr = string(re.ReplaceAllFunc([]byte(addr), func(m []byte) []byte {
			if string(m) == "%h" {
				return []byte(alias)
			}
			return []byte("%%")
		}))
	} else {
		addr = alias
	}
	var known_hosts ssh.HostKeyCallback
	switch ssh_conf(alias, "StrictHostKeyChecking") {
		case "accept-new":
			known_hosts = global.known_hosts.add
		case "no":
			known_hosts = global.known_hosts.replace
		case "off":
			known_hosts = global.known_hosts.ignore
		default:
			known_hosts = global.known_hosts.strict
	}
	tout, _ := time.ParseDuration(ssh_conf(alias, "ConnectTimeout"))
	return host{
		Alias: alias,
		Labels: labels,
		Addr: addr,
		Port: ssh_conf(alias, "Port"),
		SSH: ssh.ClientConfig{
			User: ssh_conf(alias, "User"),
			Auth: hostAuthMethods(alias),
			HostKeyCallback: known_hosts,
			HostKeyAlgorithms: strings.Split(ssh_conf(alias, "HostKeyAlgorithms"), ","),
			Timeout: tout,
		},
	}
}

func prepareHosts () []host {
	var hosts []host
	var filter cel.Program
 	if global.config.Hosts.Filter != "" {
		filter = getCEL(global.config.Hosts.Filter, nil)
	}

	var lines []string
	if global.config.Hosts.File != "" {
		content, err := os.ReadFile(global.config.Hosts.File)
		if err != nil {
			pterm.Fatal.Println(err)
		}
		lines = strings.Split(string(content), "\n")
	}
	if global.config.Hosts.Directive != "" {
		directives, _ := global.ssh_config.GetAll("", global.config.Hosts.Directive)
		lines = append(lines, directives...)
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		hostent := hostConfig(line)
		queryHostStats(&hostent)
		if filter == nil || evalCEL(filter, reflect.TypeOf(true), []any{hostent}, map[string]any{
			"Config": global.config, "Session": global.session, "Stats": global.stats,
		}).(bool) {
			hosts = append(hosts, hostent)
		}
	}

	global.session.Count = len(hosts)
	if global.config.Hosts.Order != "" {
		order(global.config.Hosts.Order, hosts)
	}
	return hosts
}

func updateStats (res result) {
	global.session.Done++
	if res.SSH == nil && res.Cmd == nil {
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

func formatRes (res result, prog cel.Program) string {
	extra := map[string]any{
		"Status"	: "OK",
		"Arrow"		: color.GreenString("->"),
		"SSH"		: fmt.Sprintf("%v", res.SSH),
		"Cmd"		: fmt.Sprintf("%v", res.Cmd),
		"Upload"	: fmt.Sprintf("%v", res.Upload),
		"Download"	: fmt.Sprintf("%v", res.Download),
	}
	if res.SSH != nil || res.Cmd != nil {
		extra["Status"] = "ERR"
		extra["Arrow"] = color.RedString("=:")
	}
	line :=	evalCEL(prog, reflect.TypeOf("String"), []any{res, extra}, map[string]any{
		"Config": global.config, "Session": global.session, "Stats": global.stats,
	})
	return line.(string)
}

func printRes (res result, prog cel.Program) {
	line := formatRes(res, prog)
	if line != "" {
		pterm.Println(line)
	}
}

func printToScreen(results []result) {
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

func progressUpdate (incr int) {
	if global.stopping {
		return
	}
	paused := ""
	if global.paused {
		paused = "[PAUSED]"
	}
	if incr > 0 {
		global.progress.Add(incr)
	}
	var est time.Duration
	if global.session.Count > 0 {
//		est = global.session.Avg * time.Duration(global.session.Count - global.session.Done)
		est = (global.session.Duration/time.Duration(global.session.Done)) * time.Duration(global.session.Count - global.session.Done)
	}
	global.progress.UpdateTitle(fmt.Sprintf("%s %s %d/%d conns, %d OK, %d ERR, %s avg; ETA: %s", version,
		paused, global.pool.GetCurrent(), global.pool.GetSize(), global.session.Ok, global.session.Err, global.session.Avg, est,
	))
}

func prompt (msg string) (string) {
	global.progress.WithRemoveWhenDone(true).Stop()
	pass, _ := pterm.DefaultInteractiveTextInput.WithMask("*").Show(msg)
	global.progress.WithRemoveWhenDone(false).Start()
	return pass
}

func renderPath (prog cel.Program, res result) string {
	val := evalCEL(prog, reflect.TypeOf("string"), []any{res}, map[string]any{
		"Config": global.config, "Session": global.session, "Stats": global.stats,
	})
	path := val.(string)
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0750)
	if err != nil {
		pterm.Warning.Println(err)
		return ""
	}
	return path
}

func renderRes (res result, prog cel.Program) {
	updateStats(res)
	if prog != nil {
		printRes(res, prog)
	}
	if global.db != nil {
		global.db.Create(&HostData{SessionID: global.sessdata.ID, Time: res.Time, Host: res.Host.Alias, Out: res.Out, Failed: res.Cmd != nil})
	}
	progressUpdate(1)
}

func upload (ftp *sftp.Client, upload *Transfer) error {
	local, err := os.Open(upload.from)
	if err != nil {
		return err
	}
	defer local.Close()

	remote, err := ftp.Create(upload.to)
	if err != nil {
		return err
	}
	defer remote.Close()

	_, err = io.Copy(remote, local)
	return err
}

func download (ftp *sftp.Client, download *Transfer) error {
	local, err := os.Create(download.to)
	if err != nil {
		return err
	}
	defer local.Close()

	remote, err := ftp.Open(download.from)
	if err != nil {
		return err
	}
	defer remote.Close()

	if _, err = io.Copy(local, remote); err != nil {
		return err
	}

	return local.Sync()
}

func runCmd (client *ssh.Client, job job, res *result) {
	session, err := client.NewSession()
	if err != nil {
		res.SSH = err
		return
	}
	defer session.Close()
	agent.RequestAgentForwarding(session)
	cmd := strings.Join(job.cmd, " ")
	if len(job.cmd) > 1 {
		cmd = shellescape.QuoteCommand(job.cmd)
	}
//	cmd := shellescape.QuoteCommand(job.cmd)
	if out := []byte{}; job.combined {
		out, res.Cmd = session.CombinedOutput(cmd)
		res.Out = strings.TrimSuffix(string(out), "\n")
	} else {
		var stdout, stderr bytes.Buffer
		session.Stdout = &stdout
		session.Stderr = &stderr
		res.Cmd = session.Run(cmd)
		res.Out = strings.TrimSuffix(string(stdout.Bytes()), "\n")
		res.Err = strings.TrimSuffix(string(stderr.Bytes()), "\n")
	}
	if res.Cmd != nil {
		switch errtype := res.Cmd.(type) {
			case *ssh.ExitError:
				res.Exit = errtype.Waitmsg.ExitStatus()
		}
	}
}

func execJob (host host, job job) result {
	start := time.Now()
	res := result{Alias: host.Alias, Host: host}

	// SSH client
	client, err := ssh.Dial("tcp", net.JoinHostPort(host.Addr, host.Port), &host.SSH)
	if err != nil {
		pterm.Error.Println(host.Alias, err)
		res.SSH = err
		return res
	}
	defer client.Close()
	if global.auth.keyring != nil && ssh_conf(host.Alias, "ForwardAgent") != "no" {
		agent.ForwardToAgent(client, global.auth.keyring)
	}

	// SFTP client
	var ftp *sftp.Client
	if job.upload != nil || job.download != nil || job.script != "" {
		ftp, err = sftp.NewClient(client)
		if err != nil {
			res.Upload, res.Download = err, err
		}
		defer ftp.Close()
	}

	// uploads go first
	if job.upload != nil {
		res.Upload = upload(ftp, job.upload)
	}

	// then commands
	if job.script != "" {
		rnd := "/tmp/" + filepath.Base(job.script) + "." + randstr.String(32)
		err := upload(ftp, &Transfer{from: job.script, to: rnd})
		if err != nil {
			res.Cmd = err
			return res
		}
		defer ftp.Remove(rnd)
		err = ftp.Chmod(rnd, 0700)
		if err != nil {
			res.Cmd = err
			return res
		}
		if len(job.cmd) > 0 {
			job.cmd = append([]string{rnd, "&&"}, job.cmd...)
		} else {
			job.cmd = []string{rnd}
		}
	}
	runCmd(client, job, &res)

	// downloads go last
	if job.download != nil {
		job.download.to = renderPath(job.download.prog, res)
		res.Download = download(ftp, job.download)
	}

	end := time.Now()
	res.Time = end.Sub(start)

	return res
}

func parallelExec () []result {
	var results []result
	var prog cel.Program
	job := job{cmd: global.config.Command, combined: global.config.Interleaved, script: global.config.Script}
	if global.config.Print.Immed != "" {
		prog = getCEL(global.config.Print.Immed, nil)
	}
	if global.config.Download.From != "" {
		if global.config.Download.To == "" {
			global.config.Download.To = fmt.Sprintf(`"%s"`, filepath.Base(global.config.Download.From))
		}
		job.download = &Transfer{from: global.config.Download.From, prog: getCEL(global.config.Download.To, nil)}
	}
	if global.config.Upload.From != "" {
		if global.config.Upload.To == "" {
			global.config.Upload.To = filepath.Base(global.config.Upload.From)
		}
		job.upload = &Transfer{from: global.config.Upload.From, to: global.config.Upload.To}
	}
	global.pool = gpool.NewPool(int(global.config.Parallelism))
	ctx, cancel := context.WithCancel(context.Background())
	global.cancel = cancel
	for _, host := range global.hosts {
		host := host
		global.pool.Enqueue(ctx, func() {
			time.Sleep(global.config.Delay)
			result := execJob(host, job)
			renderRes(result, prog)
			results = append(results, result)
		})
		global.pause.Lock()
		global.pause.Unlock()
//		for global.paused {
//			time.Sleep(100 * time.Millisecond)
//		}
	}
	global.pool.Stop()

	return results
}

func logToFiles (results []result) {
	if global.config.Log.File == "" || global.config.Log.Template == "" {
		return
	} else if global.config.Log.Order != "" {
		order(global.config.Log.Order, results)
	}
	files := make(map[string][]string)
	fileprog := getCEL(global.config.Log.File, nil)
	filtprog := getCEL(global.config.Log.Template, nil)
	for _, res := range results {
		if lines := formatRes(res, filtprog); len(lines) > 0 {
			path := renderPath(fileprog, res)
			files[path] = append(files[path], lines)
		}
	}
	for file, lines := range files {
		if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0660); err != nil {
			pterm.Warning.Println(err)
		}
	}
}

func dbOpen () {
	if global.config.Database == "" {
		return
	}
	log_level := logger.Silent
	if global.config.Debug {
		log_level = logger.Info
	}
	db, err := gorm.Open(sqlite.Open(global.config.Database), &gorm.Config{PrepareStmt: true, Logger: logger.Default.LogMode(log_level)})
	if err != nil {
		pterm.Fatal.Println(err)
	}

	// Migrate the schema
	db.AutoMigrate(&HostData{})

	// Populate global stats:
	sess := SessData{Command: strings.Join(global.config.Command, " "), Start: time.Now(), Parallelism: global.config.Parallelism}
	db.Create(&sess)
	global.db = db.Begin()
	global.sessdata = sess
	global.stats = querySessStats()
}

func dbClose() {
	if global.db != nil {
		global.sessdata.Duration = time.Since(global.sessdata.Start)
		global.db.Save(&global.sessdata)
		global.db.Commit()
	}
}

func queryHostStats (host *host) {
	if global.db == nil {
		return
	}
	var rec HostData
	aggr := map[string]any{}
	global.db.Model(&rec).Select("COUNT(*) Count, SUM(failed) Err, COUNT(*)-SUM(failed) OK, MIN(time) Min, MAX(time) Max, AVG(time) Avg").
		Where("host = ?", host.Alias).First(&aggr)
	mapstructure.Decode(aggr, &host.Stats)
	global.db.Model(&rec).Where("host = ?", host.Alias).Order("updated_at").First(&rec)
	host.Stats.Updated = rec.UpdatedAt
	host.Stats.Last = rec.Time
}

func querySessStats () SessStats {
	var rec SessData
	var stats SessStats
	aggr := map[string]any{}
	if global.db != nil {
		global.db.Model(&rec).Select("COUNT(*) Count, MIN(duration) Min, MAX(duration) Max, AVG(duration) Avg").First(&aggr)
		mapstructure.Decode(aggr, &stats)
		global.db.Model(&rec).Order("updated_at").First(&rec)
		stats.Updated = rec.UpdatedAt
		stats.Last = rec.Duration
		global.db.Model(&rec).Select("command, COUNT(*) cnt").Order("cnt").First(&aggr)
		stats.Command = aggr["command"].(string)
	}
	return stats
}

func printHeader () {
	if global.config.Header != "" {
		pterm.Println(evalCEL(getCEL(global.config.Header, nil), reflect.TypeOf("string"), []any{}, map[string]any{
			"Config": global.config, "Session": global.session, "Stats": global.stats,
		}).(string))
	}
	if global.config.Bare {
		return
	}
	logo, _ := pterm.DefaultBigText.WithLetters(putils.LettersFromStringWithStyle(version, pterm.FgYellow.ToStyle())).Srender()
	pterm.Println(logo)
	pterm.DefaultSection.Println("Session parameters")
	pterm.Println(pterm.Yellow("* Date              	:"), pterm.Cyan(time.Now()))
	pterm.Println(pterm.Yellow("* Config file           :"), pterm.Cyan(global.config.Config))
	pterm.Println(pterm.Yellow("* Hosts file        	:"), pterm.Cyan(global.config.Hosts.File))
	pterm.Println(pterm.Yellow("* Hosts count       	:"), pterm.Cyan(len(global.hosts)))
	pterm.Println(pterm.Yellow("* Parallel instances	:"), pterm.Cyan(global.config.Parallelism))
	pterm.Println(pterm.Yellow("* Delay             	:"), pterm.Cyan(global.config.Delay))
	pterm.Println(pterm.Yellow("* Command            	:"), pterm.Cyan(global.config.Command))
	pterm.Println(pterm.Yellow("* Connect timeout       :"), pterm.Cyan(ssh_conf("", "ConnectTimeout")))
	pterm.DefaultSection.Println("Running command ...")
}

func printSummary (results []result) {
	if global.config.Summary != "" {
		pterm.Println(evalCEL(getCEL(global.config.Summary, nil), reflect.TypeOf("string"), []any{}, map[string]any{
			"Config": global.config, "Session": global.session, "Stats": global.stats,
		}).(string))
	}
	if global.config.Bare {
		return
	}
	pterm.DefaultSection.Println("Session summary")
	if global.stopping {
		pterm.Warning.Println("Session interrupted before completion")
	}
	pterm.Println(pterm.Yellow("* Date                  :"), pterm.Cyan(time.Now()))
	pterm.Println(pterm.Yellow("* Total runtime         :"), pterm.Cyan(global.session.Duration))
	pterm.Println(pterm.Yellow("* Avg(t) per host       :"), pterm.Cyan(global.session.Avg))
	pterm.Println(pterm.Yellow("* Min(t) per host       :"), pterm.Cyan(global.session.Min))
	pterm.Println(pterm.Yellow("* Max(t) per host       :"), pterm.Cyan(global.session.Max))
	pterm.Println(pterm.Yellow("* Total results         :"), pterm.Cyan(len(results)))
	pterm.Println(pterm.Yellow("* Successful            :"), pterm.Cyan(global.session.Ok))
	pterm.Println(pterm.Yellow("* Failed                :"), pterm.Cyan(global.session.Err))
}

func kbdHandler () {
	if err := keyboard.Open(); err != nil {
		pterm.Fatal.Println(err)
	}
	for {
		char, key, err := keyboard.GetKey()
		if err != nil {
			pterm.Fatal.Println(err)
		}
		if key == keyboard.KeyCtrlC {
			if global.stopping {
				os.Exit(0)
			}
			global.stopping = true
			pterm.Info.Println("Waiting for active connections to complete. Ctrl-c again to quit immediately")
			global.progress.WithRemoveWhenDone(true).Stop()
			go global.pool.Stop()
			global.cancel()
		} else if key == keyboard.KeySpace && !global.paused {
			global.paused = true
			global.pause.Lock()
			progressUpdate(0)
		} else if key == keyboard.KeyEnter && global.paused {
			global.paused = false
			global.pause.Unlock()
			progressUpdate(0)
		} else if char == '+' {
			global.pool.Resize(global.pool.GetSize() + 1)
		} else if char == '-' {
			cur := global.pool.GetSize()
			if cur > 1 {
				global.pool.Resize(cur - 1)
			}
		}
	}
}

func main () {
	global.start = time.Now()
	kong.Parse(&global.config, kong.Vars{"version": version}, kong.Configuration(konghcl.Loader, config...))

	if global.config.Debug {
		pterm.EnableDebugMessages()
	}

	ssh_config, err := ssh_config.DecodeBytes(global.config.SSH.Config)
	if err != nil {
		pterm.Fatal.Println(err)
	}
	global.ssh_config = ssh_config

	dbOpen()
	initAuth()
	global.hosts = prepareHosts()

	go kbdHandler()
	printHeader()
	global.progress, err = pterm.DefaultProgressbar.WithTotal(len(global.hosts)).WithTitle(version).WithMaxWidth(0).Start()
	if err != nil {
		pterm.Fatal.Println(err)
	}
	results := parallelExec()
	global.progress.Stop()
	dbClose()
/*
	f, _ := os.Create("messh.prof")
	if err := pprof.WriteHeapProfile(f); err != nil {
		panic(err)
	}
*/
	printToScreen(results)
	logToFiles(results)
	printSummary(results)
}
