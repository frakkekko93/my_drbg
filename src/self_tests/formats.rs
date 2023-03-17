pub fn format_message(failed: bool, alg_name: String, test_name: String, message: String) -> String{
    let mut res = String::new();

    if failed {
        res.push_str("TEST FAILED (");
        res.push_str(&alg_name);
        res.push_str(") - ");
        res.push_str(&test_name);
        res.push_str(": ");
        res.push_str(&message);
    }
    else {
        res.push_str("TEST PASSED (");
        res.push_str(&alg_name);
        res.push_str(") - ");
        res.push_str(&test_name);
        res.push_str(": ");
        res.push_str(&message);
    }

    res
}