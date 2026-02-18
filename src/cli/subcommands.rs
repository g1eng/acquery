use super::functions;
use crate::ui::query as pquery;
use aclneko::acl::Acl;
use aclneko::io::{self as policyio, read_policy_file, POLICY_FILE_PATH};
// use clap::{App, Arg, ArgMatches, Command};
use serde_json::json;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str::FromStr;

pub struct Subcommands<'a> {
    pub acl: &'a Acl,
    pub is_verbose: bool,
    pub debug: bool,
}

pub struct SearchParam {
    pub header_only: bool,
    pub search_rule: bool,
    pub with_regex: bool,
}

pub struct PatchParam {
    pub operation: Option<String>,
    pub atomic: bool,
    pub unmerge: bool,
    pub assume_yes: bool,
}

pub struct QueryParam {
    pub pattern: Option<String>,
    pub color: bool,
}

impl<'a> Subcommands<'_> {
    pub fn list_cmd(self, for_patches: bool) -> Result<(), String> {
        if for_patches {
            return policyio::list_registered_patches();
        }

        let list = self.acl.parse_acl_headers();
        if self.is_verbose {
            for h in list {
                println!("{:?}", h);
            }
        } else {
            for h in list {
                println!("{}", h);
            }
        }
        Ok(())
    }

    pub fn dump_cmd(self, with_json_format: bool) -> Result<(), String> {
        if with_json_format {
            println!("{}", json!(&self.acl.data));
        } else {
            self.acl.dump_table();
        }
        Ok(())
    }

    /// subcommand `search`:search rules which has corresponding a header or
    /// a rule which matches given query.
    ///
    pub fn search_cmd(self, query: Option<String>, param: SearchParam) -> Result<(), String> {
        let mut q = String::new();

        match query {
            Some(query) => {
                q = query;
            }
            None => {
                eprint!("acl query: ");
                _ = std::io::stdin()
                    .read_line(&mut q)
                    .map_err(|e| e.to_string())?;
            }
        }

        if self.is_verbose {
            println!("policy: total {} lines", self.acl.len());
            println!("pattern: {}", &q);
        }

        if param.header_only {
            let list = self.acl.parse_acl_headers_by_pattern(q.as_str());
            if list.len() == 0 {
                return Err(String::from("no policy found"));
            } else {
                for h in list {
                    println!("{}", h);
                }
                return Ok(());
            }
        }

        let set: Acl;
        match param.search_rule {
            true => {
                set = match param.with_regex {
                    true => self.acl.parse_acl_by_rule_with_regex(&q)?,
                    false => self.acl.parse_acl_by_rule(&q.trim_end())?,
                }
            }
            false => {
                set = match param.with_regex {
                    true => {
                        if self.is_verbose {
                            println!("matching mode: regex")
                        }
                        self.acl.parse_acl_by_header_with_regex(&q)?
                    }
                    false => {
                        if self.is_verbose {
                            println!("matching mode: query")
                        }
                        self.acl.parse_acl_by_header(&q.trim_end())?
                    }
                }
            }
        }
        if set.len() != 0 {
            println!("{}", set);
            Ok(())
        } else {
            Err("no ACLs found".to_string())
        }
    }

    pub fn apply_cmd(self, source: Option<&'a String>, param: PatchParam) -> Result<(), String> {
        let mut read_from_stdin = false;
        match source {
            None => read_from_stdin = true,
            Some(v) if v == "-" => read_from_stdin = true,
            _ => {}
        }

        if read_from_stdin {
            if self.is_verbose || self.debug {
                eprintln!("reading policy from stdin...");
            }
            if param.operation.is_some() {
                eprintln!("operation intrusion is not supported for stdin");
            }
            return policyio::apply_acl_stdin();
        }
        // If apply subcommand is invoked with an argument with exist path,
        // it assumes the file as a policy patch and try to apply it.
        let mut patch = policyio::read_policy_file(source.unwrap())?;

        if let Some(op) = param.operation {
            patch.set_op(&op)?;
        }

        let msg = format!("======== PATCH ========\n\x1B[32m{}\x1B[0m", patch)
            + "=======================\n\n"
            + "Are you sure to apply this policy patch? [y/n]: ";
        if param.assume_yes || functions::prompt(&msg) {
            let res: Result<(), String>;
            match param.atomic {
                true => res = policyio::apply_acl_atomic(patch.clone()),
                false => res = policyio::apply_acl(patch.clone()),
            }
            res
        } else {
            eprintln!("canceled.");
            Ok(())
        }
    }

    /// subcommand `remove`: removes a policy patch from applied policy
    ///
    pub fn remove_cmd(self, source: Option<&'a String>, param: PatchParam) -> Result<(), String> {
        let mut read_from_stdin = false;
        match source {
            None => read_from_stdin = true,
            Some(v) if v == "-" => read_from_stdin = true,
            _ => {}
        }

        if read_from_stdin {
            if self.is_verbose {
                eprintln!("reading policy header from stdin...");
            }
            match param.unmerge {
                true => return policyio::unmerge_acl_from_stdin(&self.acl),
                false => return policyio::clear_acl_from_stdin(),
            }
        }
        let mut patch = policyio::read_policy_file(&source.unwrap()).map_err(|e| e.to_string())?;
        match param.operation {
            Some(op) => {
                patch.set_op(&op)?;
            }
            None => {}
        }
        let msg = format!("======== PATCH ========\n\x1B[31m{}\x1B[0m", patch)
            + "=======================\n\n"
            + "Are you sure to remove this header? [y/n]: ";
        if param.assume_yes || functions::prompt(&msg) {
            let res: Result<(), String>;
            match param.atomic {
                true => res = policyio::remove_acl_atomic(&patch, &self.acl),
                false => match param.unmerge {
                    true => res = policyio::unmerge_acl(&patch, &self.acl),
                    false => res = policyio::remove_acl(&patch, &self.acl),
                },
            }
            if self.is_verbose {
                println!("\x1B[7mremoved\x1B[0m");
            }
            res
        } else {
            eprintln!("canceled.");
            Ok(())
        }
    }

    /// subcommand `query`: query policy violation
    ///
    pub fn query_cmd(self, param: QueryParam) -> Result<(), String> {
        if self.is_verbose {
            eprintln!("target pattern: {:?}", param.pattern.as_ref());
        }
        if let Some(pattern) = param.pattern {
            let mut query_listener = pquery::Query::new(&pattern).map_err(|e| e.to_string())?;
            query_listener.listen_policy_violation()
        } else {
            let mut query_listener = pquery::Query::new(".").map_err(|e| e.to_string())?;
            query_listener.listen_policy_violation()
        }
    }

    /// subcommand: `clear`: clear the system policy (dangerous)
    ///
    pub fn clear_cmd(self) -> Result<(), String> {
        if self.is_verbose {
            println!("targets:");
            self.acl.list_acl_headers();
        }
        policyio::clear_acl(&read_policy_file(POLICY_FILE_PATH)?)
    }

    /// subcommand: `reload`: discard any paches and reload the default system policy
    ///
    pub fn reload_cmd(self) -> Result<(), String> {
        let mut reader =
            BufReader::new(File::open(policyio::POLICY_FILE_PATH).map_err(|e| e.to_string())?);
        let mut sbuf = vec![];
        reader.read_until(0, &mut sbuf).map_err(|e| e.to_string())?;
        let new_acl = Acl::from_str(std::str::from_utf8(&sbuf).unwrap())?;
        if self.is_verbose {
            println!("clear targets:\x1B[31m");
            self.acl.list_acl_headers();
            println!("\x1B[0m");
        }
        policyio::clear_acl(&read_policy_file(POLICY_FILE_PATH)?)?;
        if self.is_verbose {
            println!("reload targets:\x1B[32m");
            new_acl.list_acl_headers();
            print!("\x1B[0m");
        }
        policyio::apply_acl(new_acl)
    }
}
