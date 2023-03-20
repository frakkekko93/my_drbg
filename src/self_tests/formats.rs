/*  Function used to format a single log message. */
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

/*  Checks if the result passed is equal to the expected value and shows the appropriate desired message. */
pub fn check_res<T: std::cmp::PartialEq>(result: T, expected: T, test_name: String, module_name: String, fail_msg: String, succ_msg: String) -> usize {
    let mut test_id = "".to_string();
    test_id.push_str(test_name.as_str());
    if result != expected {
        println!("{}", format_message(true, module_name, test_id, fail_msg));

        return 1;
    }
    else {
        println!("{}", format_message(false, module_name, test_id, succ_msg));

        return 0;
    }
}