// use crate::proto::c7_operation::c7_rps_client;

use crate::cli::subcommands::{PatchParam, QueryParam, SearchParam};

use super::subcommands;
use aclneko::acl::Acl;
use aclneko::io::{read_policy_file, POLICY_INTERFACE_PATH};
use clap::{Parser, Subcommand};

// pub struct Command {}

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,

    /// target policy file
    #[arg(short,default_value_t=String::from(POLICY_INTERFACE_PATH))]
    file: String,

    /// increase verbosity
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// turn on debug mode
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

/// An alternative policy management interface for Caitsith
#[derive(Subcommand, Debug)]
pub enum Command {
    /// List ACL blocks
    #[command(alias = "ls")]
    List {
        /// list registered patches
        #[arg(short, long, default_value_t = false)]
        patches: bool,
    },
    /// Dump the policy
    Dump {
        /// dump ACLs in json format
        #[arg(short, long, default_value_t = false)]
        json: bool,
    },
    /// Search ACLs
    #[command(alias = "s")]
    Search {
        /// full-line, priority or operation of target ACL blocks
        pattern: Option<String>,
        /// perform the search for rule lines
        #[arg(short, long, default_value_t = false)]
        rule: bool,
        /// list output just for headers
        #[arg(long, default_value_t = false)]
        headeronly: bool,
        /// search ACLs with given regex pattern
        #[arg(long, default_value_t = false)]
        regex: bool,
    },
    /// Query policy violation
    #[command(alias = "q")]
    Query {
        /// pattern to filter targets for interactive triage
        #[arg(short, long)]
        pattern: Option<String>,
        // #[arg(short, long, default_value_t = true)]
        // color: bool,
    },
    /// Apply policy patch
    #[command(alias = "a")]
    Apply {
        /// policy patch file to be applied
        source: Option<String>,
        /// strictly apply single ACL patch
        #[arg(short, long, default_value_t = false)]
        atomic: bool,
        /// replace operation with specified one (e.g. --op chgrp)
        #[arg(short, long)]
        op: Option<String>,
        /// do not confirm changes for the policy modification
        #[arg(short, long, default_value_t = false)]
        yes: bool,
    },
    /// Remove policy patch
    #[command(alias = "r")]
    Remove {
        /// policy patch file to be removed
        source: Option<String>,
        /// strictly remove single ACL patch
        #[arg(short, long, default_value_t = false)]
        atomic: bool,
        /// not remove ACL blocks by header, but unmerge rules inside ACLs
        #[arg(short, long, default_value_t = false)]
        unmerge: bool,
        /// replace operation with specified one (e.g. --op chgrp)
        #[arg(short, long)]
        op: Option<String>,
        /// do not confirm changes for the policy modification
        #[arg(short, long, default_value_t = false)]
        yes: bool,
    },
    /// Flush all preset policy
    Clear {},
    /// Reload the default policy
    Reload {},
}

pub fn run() -> Result<(), String> {
    let args = Cli::parse();
    let mut acl = Acl::new();
    match args.command {
        Command::Query { pattern } => {}
        _ => {
            acl = read_policy_file(&args.file)?;
        }
    }
    let args = Cli::parse();
    let cmd = subcommands::Subcommands {
        acl: &acl,
        is_verbose: args.verbose,
        debug: args.debug,
    };
    match args.command {
        Command::List {
            patches: for_patches,
        } => cmd.list_cmd(for_patches),
        Command::Dump { json } => cmd.dump_cmd(json),
        Command::Search {
            pattern,
            rule,
            headeronly,
            regex,
        } => cmd.search_cmd(
            pattern,
            SearchParam {
                header_only: headeronly,
                search_rule: rule,
                with_regex: regex,
            },
        ),
        Command::Apply {
            source,
            atomic,
            op,
            yes,
        } => cmd.apply_cmd(
            source.as_ref(),
            PatchParam {
                atomic: atomic,
                operation: op,
                assume_yes: yes,
                unmerge: false,
            },
        ),
        Command::Remove {
            source,
            atomic,
            unmerge,
            op,
            yes,
        } => cmd.remove_cmd(
            source.as_ref(),
            PatchParam {
                atomic: atomic,
                operation: op,
                assume_yes: yes,
                unmerge: unmerge,
            },
        ),
        Command::Query { pattern } => cmd.query_cmd(QueryParam {
            pattern: pattern,
            color: true,
        }),
        Command::Reload {} => cmd.reload_cmd(),
        Command::Clear {} => cmd.clear_cmd(),
    }
}
