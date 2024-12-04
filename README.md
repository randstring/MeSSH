
# <img src="https://github.com/randstring/MeSSH/raw/main/logo.png">

[![MeSSH 0.9.3](https://img.shields.io/badge/MeSSH-0.9.3-blue.svg)](https://choosealicense.com/licenses/mit/)

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)

High performance, simultaneous command execution on many hosts over SSH.

A personal take on mass SSH tailored to my personal needs, but possibly useful to others.

## Features

- Support for high and configurable concurrency
- File upload/download
- Programmable screen and log output
- Pause and resume
- Progress & status bar
- Run shell commands or upload & execute files

## Installation

You need to have at least Go 1.19 available to compile the source.

```bash
git clone https://github.com/randstring/MeSSH.git
cd MeSSH
go build messh.go
```

## Demo

[![asciicast](https://asciinema.org/a/rVREA0wWpLGKlRsypHlMkiWTd.svg)](https://asciinema.org/a/rVREA0wWpLGKlRsypHlMkiWTd)


## Examples

Run simple command
```bash
messh -f hostlist.txt uname -a
```

Upload and run whole script
```bash
echo "uname -a" > script.sh
echo "date" >> script.sh
messh -f hostlist.txt -x script.sh
```

Transfer a file
```bash
messh -f hostlist.txt -U sample.txt cat sample.txt
```
Log output
```bash
messh -f hostlist.txt -l 'Alias+".txt"' --log-template 'Out' uname -a
```
## Related

- [Mass Parallel Secure Shell](https://github.com/ndenev/mpssh)

- [mpssh-py - python fork of mpssh](https://github.com/famzah/mpssh-py)


## License

[MIT](https://choosealicense.com/licenses/mit/)


## Authors

[@randstring](https://github.com/randstring)

