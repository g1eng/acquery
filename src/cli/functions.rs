use aclneko::acl::Acl;
use aclneko::syntax::{Op, Resource, Verb};
use std::io::stdin;
use std::str;

pub fn prompt(msg: &str) -> bool {
    eprint!("{}", msg);
    let mut buf = String::new();
    match stdin().read_line(&mut buf) {
        Ok(_) => match buf.replace("\n", "").as_str() {
            "yes" | "YES" | "y" | "Y" => true,
            "no" | "NO" | "n" | "N" => false,
            _ => {
                eprintln!("answer with yes or no.");
                prompt(msg)
            }
        },
        Err(_) => {
            eprintln!("error");
            prompt(msg)
        }
    }
}

// pub fn show_stat(mut acl: Acl, line: Option<&str>) -> Result<(), String> {
//     let mut is_op_query = false;
//     match line {
//         Some(n) => {
//             acl = acl.get_acl_by_header(n.clone())?;
//             println!("query: {}", n);
//             if Op::from(n) != Op::Error {
//                 is_op_query = true;
//             }
//         }
//         None => {}
//     };
//
//     let mut c = 0;
//     for i in acl.rule_len() {
//         c += i;
//     }
//     println!("total ACLs: {}", acl.len());
//     println!("total rules: {}", c);
//
//     let mut a = 0;
//     let mut d = 0;
//     for v in acl.rule_count_verb(Verb::Allow) {
//         a += v;
//     }
//     for v in acl.rule_count_verb(Verb::Deny) {
//         d += v;
//     }
//     println!("allow: {}  deny: {}", a, d);
//     println!();
//
//     let mut op_buf = vec![];
//     for o in Op::list() {
//         let op_count = acl.count_op(o);
//         if op_count != 0 {
//             op_buf.push((o, op_count));
//         }
//     }
//     if is_op_query == false {
//         println!("[operation statics for headers]");
//         let mut i = 1;
//         for o in op_buf {
//             if i % 4 != 0 {
//                 print!("  {}: {}\t", o.0.as_str(), o.1);
//             } else {
//                 println!("  {}: {}", o.0.as_str(), o.1);
//             }
//             i += 1;
//         }
//         if (i - 1) % 4 != 0 {
//             println!();
//         }
//         println!();
//     }
//
//     println!("[resource statics for headers]");
//     let mut res_buf = vec![];
//     let mut i = 1;
//     for r in Resource::list() {
//         let filter = move |header: AclHeader| {
//             for attr in &header.attr {
//                 if attr.0 == r {
//                     return true;
//                 }
//             }
//             false
//         };
//         let res_count = acl.count(filter);
//         if res_count != 0 {
//             res_buf.push((r, res_count));
//         }
//     }
//     for r in res_buf {
//         if i % 4 != 0 {
//             print!("  {}: {}\t", r.0.as_str(), r.1);
//         } else {
//             println!("  {}: {}", r.0.as_str(), r.1);
//         }
//         i += 1;
//     }
//     if (i - 1) % 4 != 0 {
//         println!();
//     }
//     Ok(())
// }

// show difference between source Acl and destination Acl.
//
// pub fn diff_acls(src: &Acl, dst: &Acl) {
//     let window_size = if src.len() > dst.len() { src.len() } else { dst.len() } ;
// }
//
