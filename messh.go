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
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/mitchellh/mapstructure"

	"github.com/alessio/shellescape"

	"gorm.io/gorm"
	"gorm.io/driver/sqlite"

_	"runtime/pprof"
)

const (
	version = "MeSSH 0.7.8"
)

var config = []string {"messh.conf", "~/.messh.conf"}

type host struct {
	Host	string
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
	Host		string
	Out			string
	Err			string
	Exit		int
	SSH			error
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

type HostData struct {
	gorm.Model
	Host		string
	Out			string
	Failed		bool
	Time		time.Duration
	SessionID	uint
	Session		SessData
}

type SessData struct {
	gorm.Model
	Command		string
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
}

type SessStats struct {
	Count		int
	Cmd			string
	AvgHosts	float32
	Avg			time.Duration
	Min			time.Duration
	Max			time.Duration
	Last		time.Duration
	Period		time.Duration
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
	sessid		uint
	paused		bool
	stopping	bool
	known_hosts	struct {
		strict	ssh.HostKeyCallback
		add		ssh.HostKeyCallback
		replace	ssh.HostKeyCallback
		ignore	ssh.HostKeyCallback
	}
	auth		struct {
		prompt		sync.Mutex
		keyring		agent.Agent
		agent		ssh.AuthMethod
		password	ssh.AuthMethod
		kbi			ssh.AuthMethod
		keys		map[string]ssh.AuthMethod
		interactive	map[string] string
		pwinput		string
	}
}

type Config struct {
	Bare			bool			`short:"b" negatable help:"bare output; don't print extra headers or summary"`
	Config			kong.ConfigFlag	`short:"c" help:"load configuration from file"`
	Combined		bool			`short:"C" negatable default:"true" help:"combine stdout and stderr in Out"`
	Header			string			`short:"H" help:"custom header expression"`
	Summary			string			`short:"Z" help:"custom summary expression"`
	Delay			time.Duration	`short:"d" default:"10ms" help:"delay each new connection by the specified time, avoiding congestion"`
	Database		string			`short:"E" default:"messh.db" help:"persist session data in a SQLite database at the specified location"`
	Timeout			time.Duration	`short:"t" default:"30s" help:"connection timeout"`
	Parallelism		uint			`short:"m" aliases:"max" default:1 help:"max number of parallel connections"`
	Hosts			struct {
		File		string			`short:"f" aliases:"read" required type:"existingfile" help:"hosts file"`
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
		From		string			`short:"U" type:"existingfile" placeholder:"LOCAL" help:"local path expression to upload"`
		To			string			`aliases:"ut" placeholder:"REMOTE" help:"remote file path for upload"`
	}								`embed prefix:"upload-"`
	Download		struct	{
		From		string			`short:"D" placeholder:"REMOTE" help:"remote file to download"`
		To			string			`aliases:"dt" placeholder:"EXPR(res)string" help:"local path expression to download files to"`
	}								`embed prefix:"download-"`
	SSH				[]byte			`short:"S" name:"ssh-config" type:"filecontent" default:"~/.ssh/config" help:"path to SSH config for host/auth configuration"`
	Auth			struct {
		User			string			`short:"u" default:"root" help:"default user if not specified in hosts"`
		Password		string			`short:"P" help:"SSH password to use when connecting"`
		Key				string			`short:"K" placeholder:"KEY[:pass]" help:"SSH key for authentication, has precedence over password"`
		Agent			bool			`negatable default:"true" help:"allow using SSH agent for authentication"`
	}								`embed prefix:"auth-"`
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
			cel.Variable("Hist",		cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("a",			cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("b",			cel.MapType(cel.StringType, cel.AnyType)),
			cel.Variable("Hosts",		cel.ListType(cel.AnyType)),
			cel.Variable("Time",		types.DurationType),
			cel.Variable("Host",		cel.StringType),
			cel.Variable("Out",			cel.StringType),
			cel.Variable("Err",			cel.StringType),
			cel.Variable("Cmd",			cel.StringType),
			cel.Variable("SSH",			cel.StringType),
			cel.Variable("Upload",		cel.StringType),
			cel.Variable("Download",	cel.StringType),
			cel.Variable("Host32",		cel.StringType),
			cel.Variable("Arrow",		cel.StringType),
			cel.Variable("Status",		cel.StringType),
			cel.Variable("Exit",		cel.IntType),
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

// Get a ssh_config value for the specified host with fallback to global or default values
func ssh_conf (alias string, key string) string {
	val, _ := global.ssh_config.Get(alias, key)
	if val == "" {
		val = ssh_config.Default(key)
	}
	return val
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

	global.auth.password = ssh.PasswordCallback(func() (string, error) {
		global.auth.prompt.Lock()
		if global.auth.pwinput == "" {
			global.auth.pwinput = prompt("Please enter a password as a last auth measure")
		}
		global.auth.prompt.Unlock()
		return global.auth.pwinput, nil
	})
	global.auth.kbi = ssh.KeyboardInteractive(func(user, inst string, questions []string, echoes []bool) (answers []string, err error) {
		global.auth.prompt.Lock()
		for _, q := range questions {
			if global.auth.interactive[q] == "" {
				global.auth.interactive[q] = prompt(q)
			}
			answers = append(answers, global.auth.interactive[q])
		}
		global.auth.prompt.Lock()
		return
	})
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
				auth = append(auth, global.auth.kbi)
			}
		case "password":
			if pass := ssh_conf(alias, "Password"); pass != "" {
				auth = append(auth, ssh.Password(pass))
			} else if ssh_conf(alias, "PasswordAuthentication") != "no" {
				auth = append(auth, global.auth.password)
			}
		}
	}
//spew.Dump(auth)

	return
}

func hostConfig (line string) host {
	var labels []string
	line = strings.TrimSpace(line)
	fields := strings.Fields(line)
	if len(fields) < 1 || len(fields) > 2 {
		panic("broken record in hosts file")
	} else if len(fields) > 1 {
		labels = strings.Split(fields[1], ",")
	}
	alias := fields[0]
	addr := ssh_conf(alias, "HostName")
	if addr == "" {
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
	tout, err := time.ParseDuration(ssh_conf(alias, "ConnectTimeout"))
	if err != nil {
		tout = global.config.Timeout
	}
	return host{
		Host: alias,
		Labels: labels,
		Addr: addr,
		Port: ssh_conf(alias, "Port"),
		SSH: ssh.ClientConfig{
			User: ssh_conf(alias, "User"),
			Auth: hostAuthMethods(alias),
			HostKeyCallback: known_hosts,
//			HostKeyAlgorithms: strings.Split(ssh_conf(alias, "HostKeyAlgorithms"), ","),
			Timeout: tout,
		},
	}
}

func prepareHosts (path string) []host {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
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
		hostent := hostConfig(line)
		if filter == nil || evalCEL(filter, reflect.TypeOf(true), []any{hostent}, map[string]any{"Config":global.config}).(bool) {
			hosts = append(hosts, hostent)
		}
		// fetch from DB
	}

	if global.config.Hosts.Order != "" {
		order(global.config.Hosts.Order, hosts)
	}
	return hosts
}

func updateStats (res result) {
	global.session.Count++
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
		"Host32":	fmt.Sprintf("%32s", res.Host),
		"Status":	"OK",
		"Arrow"	:	color.GreenString("->"),
	}
	if res.SSH != nil || res.Cmd != nil {
		extra["Status"] = "ERR"
		extra["Arrow"] = color.RedString("=:")
	}

	line :=	evalCEL(prog, reflect.TypeOf("String"), []any{res, extra}, map[string]any{"Config": global.config, "Session": global.session})
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
	global.progress.UpdateTitle(fmt.Sprintf("%s %s %d/%d conns, %d OK, %d ERR, %s avg; ETA: %s", version,
		paused, global.pool.GetCurrent(), global.pool.GetSize(), global.session.Ok, global.session.Err, global.session.Avg,
		(global.session.Duration/time.Duration(global.session.Count)) * time.Duration(len(global.hosts) - global.session.Count),
	))
}

func prompt (msg string) (string) {
	global.progress.WithRemoveWhenDone(true).Stop()
	pass, _ := pterm.DefaultInteractiveTextInput.WithMask("*").Show(msg)
	global.progress.WithRemoveWhenDone(false).Start()
	return pass
}

func renderPath (prog cel.Program, res result) string {
	val := evalCEL(prog, reflect.TypeOf("string"), []any{res}, map[string]any{"Config": global.config, "Session": global.session})
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
		global.db.Create(&HostData{SessionID: global.sessid, Time: res.Time, Host: res.Host, Out: res.Out, Failed: res.Cmd != nil})
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

	cmd := shellescape.QuoteCommand(job.cmd)
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
	res := result{Host: host.Host}

	// SSH client
	client, err := ssh.Dial("tcp", net.JoinHostPort(host.Addr, host.Port), &host.SSH)
	if err != nil {
		pterm.Error.Println(host.Host, err)
		res.SSH = err
		return res
	}
	defer client.Close()
	if global.auth.keyring != nil && ssh_conf(host.Host, "ForwardAgent") != "no" {
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
	job := job{cmd: global.config.Command, combined: global.config.Combined, script: global.config.Script}
	if global.config.Immed != "" {
		prog = getCEL(global.config.Immed, nil)
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
	for _, host := range global.hosts {
		host := host
		global.pool.Enqueue(context.Background(), func() {
			time.Sleep(global.config.Delay)
			result := execJob(host, job)
			renderRes(result, prog)
			results = append(results, result)
		})
		for global.paused {
			time.Sleep(100 * time.Millisecond)
		}
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
	db, err := gorm.Open(sqlite.Open(global.config.Database), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	// Migrate the schema
	db.AutoMigrate(&HostData{})

	// Populate global stats:


	sess := SessData{Command: strings.Join(global.config.Command, " ")}
	db.Create(&sess)
	global.db = db
	global.sessid = sess.ID
}

func printHeader () {
	if global.config.Header != "" {
		pterm.Println(evalCEL(getCEL(global.config.Header, nil), reflect.TypeOf("string"), []any{map[string]any{"Hosts":global.hosts}}, map[string]any{
			"Config": global.config,
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
	pterm.Println(pterm.Yellow("* Connect timeout       :"), pterm.Cyan(global.config.Timeout))
	pterm.DefaultSection.Println("Running command ...")
}

func printSummary (results []result) {
	if global.config.Bare {
		return
	}
	pterm.DefaultSection.Println("Session summary")
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
		panic(err)
	}
	for {
		char, key, err := keyboard.GetKey()
		if err != nil {
			panic(err)
		}
		if key == keyboard.KeyCtrlC {
			if global.stopping {
				os.Exit(0)
			}
			global.stopping = true
			pterm.Info.Println("Waiting for active connections to complete. Ctrl-c again to quit immediately")
			global.progress.WithRemoveWhenDone(true).Stop()
			go global.pool.Stop()
		} else if key == keyboard.KeySpace && !global.paused {
			global.paused = true
			progressUpdate(0)
		} else if key == keyboard.KeyEnter && global.paused {
			global.paused = false
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

	ssh_config, err := ssh_config.DecodeBytes(global.config.SSH)
	if err != nil {
		panic(err)
	}
	global.ssh_config = ssh_config

	dbOpen()
	initAuth()
	global.hosts = prepareHosts(global.config.Hosts.File)

	go kbdHandler()
	printHeader()
	global.progress, err = pterm.DefaultProgressbar.WithTotal(len(global.hosts)).WithTitle(version).WithMaxWidth(0).Start()
	if err != nil {
		panic(err)
	}
	results := parallelExec()
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
