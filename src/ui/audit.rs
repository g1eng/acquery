use aclneko::syntax::AuditMatcher;

/// style_audit_message build a string for styled audit message.
/// An input should be a valid line for audit log of caitsith.
///
/// Any newline position is hardcoded at now.
///
pub fn style_audit_message(x: String) -> String {
    let mut res = String::new();
    let mut word_count: usize;
    let line_break = vec![4, 7, 13, 19, 22, 26, 30, 34, 38, 42, 46, 50];
    let audit = AuditMatcher::new();
    word_count = 0;
    for s in x.split_whitespace() {
        if line_break.contains(&word_count) {
            res += "  \x1B[0m\n  ";
        }
        if audit.is_uid(&s) {
            res += "\x1B[33m";
        } else if audit.is_task_exe(&s) {
            res += "\x1B[31m";
        } else if audit.is_task_ugid(&s) {
            res += "\x1B[33m";
        } else if audit.is_task_xpid(&s) {
            res += "\x1B[34m";
        } else if audit.is_task_domain(&s) {
            res += "\x1B[31m";
        } else if audit.is_path_single(&s) {
            res += "\x1B[7m\x1B[33m";
        } else if audit.is_path_ugid(&s) || audit.is_path_mod(&s) {
            res += "\x1B[33m";
        } else if audit.is_path_parent_ugid(&s) || audit.is_path_parent_mod(&s) {
            res += "\x1B[33m";
        } else if audit.is_transition(&s) {
            res += "\x1B[5m\x1B[31m"
        }
        res += s;
        res += "\x1B[0m ";
        word_count += 1;
    }
    res + "\x1B[0m "
}
