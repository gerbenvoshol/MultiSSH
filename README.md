# MultiSSH
MultiSSH is a systems administration tool that runs Linux/Unix commands on multiple ssh servers, it is a lightweight command line tool that is easy to setup and use. It is designed to be easily used in scripts or standalone.

Setup
-----

Install dependencies for Debian/Ubuntu, run in your Terminal shell:

```shell
sudo apt-get install libssh-dev
```
Or for Red Hat/CentOS:
```shell
sudo yum install libssh-devel
```
Then compile using make:
```shell
make
```
Or compile manually:
```shell
gcc multissh.c -o multissh -lssh
```
Usage instructions
------------------
You must create a file named 'sshservers' which contains a list of ssh servers and credentials before MultiSSH is run, you must add one line per server, in the format:

sshserverhost:sshserverport:sshserverusername:sshserverpassword

The sshservers.example file is an example of what an 'sshservers' file should look like.

After compiling, MultiSSH can be run as follows:

```shell
./multissh 'command(s)'
```

**Command Line Options:**

- `-f FILE` - Use a custom SSH servers file instead of the default 'sshservers'
- `-s LIST` - Select specific servers using comma-separated server:port list
- `-h` - Show help message

**Examples:**

Basic usage (uses default 'sshservers' file):
```shell
./multissh 'uptime'
```

Using a custom servers file:
```shell
./multissh -f /path/to/my-servers 'df -h'
```

Selecting specific servers:
```shell
./multissh -s '192.168.1.10:22,192.168.1.11:22' 'ps aux'
```

Combining options:
```shell
./multissh -f production-servers -s '10.0.1.5:22,10.0.1.6:22' 'systemctl status nginx'
```

When running multiple commands, each command must be separated with a semicolon ';' and all commands must be within quotes, for example:
```shell
./multissh 'ps; free -m'
```

**Build System:**

Use the provided Makefile for easy building:
```shell
make            # Build the project
make clean      # Clean build artifacts  
make install    # Install to /usr/local/bin (requires sudo)
make uninstall  # Remove from /usr/local/bin (requires sudo)
make check-deps # Check if dependencies are installed
make help       # Show build system help
```
Tested and confirmed working on Ubuntu, CentOS, and OS X. Should work on any Linux distribution and *BSD.
