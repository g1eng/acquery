use super::audit::*;
use aclneko::acl::Acl;
use aclneko::io::*;
use aclneko::syntax::{AuditMatcher, Matcher, Op};
use nix::poll::{self, PollTimeout};
use std::fs::{File, OpenOptions};
use std::io::prelude::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::str;
use std::str::FromStr;

use console::Term;

/// Query represents a query request interface with its internal state.
/// query id is not held on this struct and should be supplied for a method
/// as an argument.
///
pub struct Query {
    pub styled: bool,
    pub query_interface: File,
    pub policy_interface: File,
    pub filter: regex::Regex,
    pub optin_filter: Vec<regex::Regex>,
    rule_addition_history: Vec<String>,
}

// query internal
impl Query {
    /// query_policy_violation wait for policy violations and supply interactive
    /// treatment for them.
    ///
    pub fn new(filter_pattern: &str) -> Result<Query, String> {
        let query_interface = OpenOptions::new()
            .read(true)
            .write(true)
            .open(QUERY_INTERFACE_PATH)
            .map_err(|e| e.to_string())?;

        let policy_interface = OpenOptions::new()
            .read(true)
            .write(true)
            .open(POLICY_INTERFACE_PATH)
            .map_err(|e| e.to_string())?;

        let mut operations = String::from("^(");
        for o in Op::list() {
            if operations.len() > 2 {
                operations += "|";
            }
            operations += o.as_str();
        }
        operations += ")";

        let rule_addition_history: Vec<String> = vec![String::new(); 100];
        let filter = regex::Regex::new(filter_pattern).map_err(|e| e.to_string())?;
        let optin_filter = vec![regex::Regex::new("$$^^").unwrap(); 10];
        Ok(Query {
            styled: true,
            query_interface,
            policy_interface,
            filter,
            optin_filter,
            rule_addition_history,
        })
    }

    //deny simply denies policy violation on demand.
    //
    fn deny(&mut self, query_id: &str) {
        let ans = format!("A{}=2\n", query_id);
        _ = self.query_interface.write(ans.as_bytes());
        eprintln!("\x1B[7m\x1B[33mrejected\x1B[0m\n");
    }

    //show_query shows the ACL block which is related to the policy violation,
    //which violate at least one rule with a `deny` operand in the ACL block.
    //
    fn show_query(&mut self, query_id: &str) {
        let mut buf = vec![];
        let query = format!("Q={}\n", query_id);
        _ = self.policy_interface.write(query.as_bytes());
        _ = self.policy_interface.read_to_end(&mut buf);
        eprintln!("\n---------------------\n\x1B[47m\x1B[30m[selected policy]\x1B[0m");
        let msg = String::from_utf8(buf).unwrap();
        for s in msg.split("\n") {
            if !s.starts_with("#") && !s.is_empty() {
                eprintln!("\x1B[32m{}\x1B[0m", s);
            }
        }
        eprintln!("---------------------");
    }

    //permit temporary permits pending query for a policy violation.
    //
    fn permit(&mut self, query_id: &str) {
        let ans = format!("A{}=1\n", query_id);
        _ = self.query_interface.write(ans.as_bytes());
        eprintln!("y: \x1B[42m\x1B[30mpermit\x1B[0m");
        eprintln!();
    }

    //reevaluate evaluates the policy violation trial with the latest policy.
    //It is useful for policy patching from the other process.
    //
    fn reevaluate(&mut self, query_id: &str) {
        let ans = format!("A{}=3\n", query_id);
        _ = self.query_interface.write(ans.as_bytes());
        eprintln!("r: \x1B[44m\x1B[30mre-evaluate\x1B[0m");
        eprintln!();
    }

    //reset_filter sets filtering pattern for interactive quering.
    //If a filter pattern is set, only the policy violation with a matched
    //pattern will be queried interactively.
    //
    //Any opt-in filters are cleared after the reset of the filter .
    //
    fn reset_filter(&mut self) {
        eprint!("\nfilter pattern: ");
        let term = Term::stdout();
        loop {
            if let Ok(n) = term.read_line_initial_text(self.filter.as_str()) {
                match regex::Regex::new(n.as_str()) {
                    Ok(p) => {
                        self.filter = p;
                        self.optin_filter.clear();
                        break;
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                    }
                }
            }
        }
        //eprintln!("\n{}", audit_message);
    }

    //add_optin_filter appends temporary opt-in filter for preset filter.
    //It has no effect without a filter pattern set from the F command.
    //
    //A filter ignores queries unmatched for the pattern by default, but the
    //query which is matched to any of the optin filter patterns. will be
    //interactively issued.
    //
    fn add_optin_filter(&mut self) {
        eprint!("\nopt-in query pattern: ");
        let term = Term::stdout();
        loop {
            if let Ok(n) = term.read_line_initial_text(self.filter.as_str()) {
                match regex::Regex::new(n.as_str()) {
                    Ok(p) => {
                        self.optin_filter.push(p);
                        break;
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                    }
                }
            }
        }
        //eprintln!("\n{}", audit_message);
    }

    //add_new_rule appends a rule line into the ACL block violated.
    //Any rule line should have valid rule syntax which is composed of
    //priority(uint), operation(allow/deny) and attributes(key=val)
    //
    //Invalid lines are ignored without any messages.
    //
    fn add_new_rule(&mut self, query_id: &str) {
        let term = Term::stdout();
        let acl_parser = Matcher::new();
        let query = format!("Q={}\n", query_id);
        _ = self.policy_interface.write(query.as_bytes());
        let mut buf = vec![];
        _ = self.policy_interface.read_to_end(&mut buf);

        eprint!("\nenter a new rule: ");
        loop {
            let default_text = match self.rule_addition_history.last() {
                Some(l) => {
                    let mut i = 0;
                    let mut res = String::new();
                    for w in l.split_whitespace() {
                        i += 1;
                        if i > 1 {
                            res += " ";
                            res += w;
                            break;
                        } else {
                            res += w;
                        }
                    }
                    res
                }
                _ => String::new(),
            };

            if let Ok(n) = term.read_line() {
                self.rule_addition_history.push(n.clone());
                let n = String::from(" ") + n.as_str() + "\n";
                if acl_parser.is_acl_rule(&n) {
                    let audit = AuditMatcher::new();
                    if audit.is_ip(&n) || audit.is_port(&n) {
                        _ = self.policy_interface.write(query.as_bytes());
                        let buf = &str::from_utf8(&buf).unwrap();
                        //debug
                        //eprintln!("\n\x1B[33mrawbuf\x1B[0m\n{}",buf);
                        let acl = Acl::from_str(buf).unwrap();
                        let h = acl.parse_acl_headers();
                        if h.len() == 0 {
                            eprintln!("ACL header for the violation not detected");
                            break;
                        } else if !h[0].op.is_net() {
                            eprintln!("ACL header is not inet ACL");
                            break;
                        }

                        let v = format!("{}\n  {}", h[0], n);
                        if let Ok(new_acl_line) = Acl::from_str(v.as_str()) {
                            //debug
                            //eprintln!("\n\x1B[33mnewacl\x1B[0m\n{:?}",new_acl_line);
                            match apply_acl(new_acl_line) {
                                Err(e) => {
                                    eprintln!("{}", e);
                                    continue;
                                }
                                _ => _ = term.write_line(" \x1B[42m\x1B[30madded\x1B[0m"),
                            }
                        } else {
                            eprintln!("invalid acl line input");
                            continue;
                        }
                    } else {
                        _ = self.policy_interface.write(n.as_bytes());
                        _ = term.write_line(" \x1B[42m\x1B[30madded\x1B[0m");
                    }
                } else {
                    eprintln!("invalid rule syntax");
                }
            }
            break;
        }
    }

    //select_applied_patch provides interactive patch selection to apply patch
    //to the live policy from user-defined patch collection.
    //
    //Any user-defined patches are assumed to be in /etc/caitsith/patch.
    //
    fn select_applied_patch(&self) {
        let term = Term::stdout();
        _ = term.write_line("");
        _ = list_registered_patches();
        _ = term.write_line("");
        _ = write!(&term, "patch to apply: ");
        if let Ok(f) = term.read_line() {
            let patch = match read_policy_file(format!("{}/{}", PATCH_DIR, f).as_str()) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{}", e);
                    return;
                }
            };
            match apply_acl(patch) {
                Ok(_) => _ = term.write_line("\x1B[42m\x1B[30mapplied\x1B[0m"),
                Err(e) => {
                    eprintln!("{}", e)
                }
            }
        }
    }

    //select_removed_patch provides interactive patch selection to remove patch
    //from the live policy, using user-defined patch collection.
    //
    // Any patches are assumed to be in /etc/caitsith/patch.
    //
    fn select_removed_patch(&self) {
        let term = Term::stdout();
        _ = term.write_line("");
        _ = list_registered_patches();
        _ = term.write_line("");
        _ = write!(&term, "patch to unmerge: ");
        if let Ok(f) = term.read_line() {
            let patch = match read_policy_file(format!("{}/{}", PATCH_DIR, f).as_str()) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("{}", e);
                    return;
                }
            };
            match unmerge_acl(&patch, &read_policy_file(POLICY_INTERFACE_PATH).unwrap()) {
                Ok(_) => _ = term.write_line("\x1B[42m\x1B[30mremoved\x1B[0m"),
                Err(e) => eprintln!("{}", e),
            }
        }
    }

    //wait_command_key provides command interface for policy violation handling.
    //
    fn wait_command_key(&mut self, query_id: &str) -> Result<(), String> {
        let term = Term::stdout();
        loop {
            if let Ok(c) = term.read_char() {
                match c {
                    's' => self.show_query(query_id),
                    'y' | 'Y' => self.permit(query_id),
                    'n' | 'N' => self.deny(query_id),
                    'r' | 'R' => self.reevaluate(query_id),
                    'f' | 'F' => self.reset_filter(),
                    'o' | 'O' => self.add_optin_filter(),
                    'q' | 'Q' => {
                        eprintln!();
                        std::process::exit(0);
                    }
                    'a' | 'A' => self.add_new_rule(query_id),
                    _ => continue,
                }
                break;
            }
        }
        Ok(())
    }

    //listen_policy_violation wait for a new policy violation and show query
    //information to handle it interactively.
    //
    //To terminate the process, use `quit` command in the interactive policy
    //violation handling.
    pub fn listen_policy_violation(&mut self) -> Result<(), String> {
        let qi_readonly = self
            .query_interface
            .try_clone()
            .map_err(|e| e.to_string())?;
        let pfd = poll::PollFd::new(qi_readonly.as_fd(), poll::PollFlags::POLLIN);
        let query_output_pattern = regex::Regex::new(r"^Q(?P<id>\d+)(-\d+)?").unwrap();

        eprintln!("monitoring policy violation...");
        let pfd_ref = &mut [pfd];

        loop {
            // poll eternally
            poll::poll(pfd_ref, PollTimeout::MAX).map_err(|e| e.to_string())?;
            let mut buf = vec![];
            let mut qbuf = vec![];

            //do query
            self.query_interface
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
            let mut i = 0;
            for s in String::from_utf8(buf.clone()).unwrap().split("\n") {
                if i % 2 == 1 {
                    buf = s.into();
                    break;
                } else {
                    qbuf = match query_output_pattern.captures(s) {
                        Some(p) => p["id"].into(),
                        None => {
                            //display audit announcement
                            eprintln!("{}", &s);
                            continue;
                        }
                    }
                }
                i += 1;
            }

            //extract query_id
            let query_id = str::from_utf8(&qbuf).unwrap();
            let mut audit_message = String::from_utf8(buf.clone()).unwrap();
            if self.styled {
                audit_message = style_audit_message(audit_message);
            } else {
                audit_message += "\n";
            }

            eprintln!("qseq: {}", query_id);
            eprintln!("{}", audit_message);

            eprint!(
                "command: (Y)es / (N)o / (A)dd / (R)etry / (S)how / (F)ilter / (O)pt-in / (Q)uit : "
            );

            let m2 = audit_message.clone();

            if self.filter.is_match(&audit_message)
                || || -> bool {
                    for i in 0..self.optin_filter.len() {
                        if self.optin_filter[i].is_match(&m2) {
                            return true;
                        }
                    }
                    false
                }()
            {
                match self.wait_command_key(query_id) {
                    Ok(_) => continue,
                    Err(_) => break,
                };
            } else {
                eprint!("\n\x1B[7m\x1B[33mautomatically ");
                self.deny(query_id);
            };
        }
        Ok(())
    }
}
