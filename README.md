`acquery` is an alternative CLI to handle policy files and policy violations for [Caitsith](https://caitsith.sourceforge.io). 

> [!WARNING]
> * PoC state.
> * Published on 2026/2/18.
> * Network functionalities are removed for the release.

# Requirement

* Linux kernel patched with [caitsith](https://caitsith.sourceforge.io)  (linux>=6.x works well)
* root priviledge

# Install

```shell-session
cargo install acquery
```

or 


```shell-session
git clone this.repo acquery
cd acquery
make
make install
```

The default install path for the binary is `/bin`. Modify PREFIX environmental variable to change installation destination. For example:

```
PREFIX=$HOME make install
```

# Usage

```
USAGE:
    acquery [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -f, --file <target>    The target policy path [default: /sys/kernel/security/caitsith/policy]
    -h, --help             Print help information
    -v, --verbose          Increase verbosity
    -V, --version          Print version information

SUBCOMMANDS:
    apply     Apply a policy patch for the system
    help      Print this message or the help of the given subcommand(s)
    list      List ACL headers
    query     Interactively query policy violation
    reload    Reload default policy
    remove    Remove a patch from the system
    search    Search ACL from policy file
```

See help messages for each subcommands.

# Tutorial

### 1. Prepare sample policy

Think about the following sample policy patch file:

```
10 acl inet_stream_connect
  0 allow port=443 task.exe="/usr/bin/curl"
  0 deny
```

This policy means that

1. permit `/usr/bin/curl` to connect to any hosts via TCP with port `443`.
2. deny any new connection other than (1).

If you apply this policy to caitsith instance, you will lost internet connection on userland (except for `/usr/bin/curl`) and also `curl` cannot connect via TCP other than port `443`.

Save this policy as `sample-policy.acl` and go next steps.

### 2. Apply, show and remove policy

To apply the policy patch `sample-policy.acl`, run next command (as root):

```
acquery apply sample-policy.acl
```

You can show applied policy with `acquery show`.
Be sure of all policies contained in the output:

```
acquery show
```

If you'd like to remove the patch from the applied set on the policy, run the following command:

```
acquery remove sample-policy.acl
```

The policy patch will be removed if there is an ACL block set completely matched to the patch.


### 3. Perform policy query for violation

You can query policy violations with the `query` subcommand:

```
acquery q 
```

The caitsith module freezes the task thread immediately when the task violates one of rules in an ACL block in the active policy.
You can perform interactive violation handling during the task freezing.

Press `y` to temporary permit the operation which violates a rule in the policy.

Press `n` to deny the operaiton.

Press `s` to show the ACL block which evaluates the policy violation.

### 4. Search ACL block from your policy

`search` subcommand filters ACL blocks with search query and output them. 

```shell
acquery search [--header-only] [--rule] [--regex] query
```

`query` is essential argument and it has different contexts for searching target.

By default, `query` should be a priority (unsigned int) or a supported syscall (e.g. read, chmod and so on.).

For the ACL block in the previous example:

```shell
acquery search 10
```

or

```shell
acquery search inet_stream_connect
```

can be valid query to match the ACL. (Also other ACLs can be matched if they met the condition.)

If you give `--regex` flag, you can perform regex match on all header line:

```shell
acquery search --regex task\.domain.+
```


`search` subcommand also can search rules inside ACL blocks with given pattern.

```shell
acquery search -r --regex task\.domain=@\(special\|normal\)
```

This query results all Acl block containing a rule with the regex pattern `task.domain=@(special|normal)"`. Any ACL blocks with such pattern will be dumped with the command.

A `query` for `--rule` option without `--regex` option, can be a full expression of a valid rule line. In such case, the command results ACLs with a rule which is completely equal to the given query.

```shell
acquery search -r "  0 deny"
```

# Author

youmeim <Suzume[at]EA.G1E.org>
