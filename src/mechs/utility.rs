/*  Performs a modular addition between a vector of bytes and a single byte. */
pub fn modular_add(num: &mut Vec<u8>, rhs: u8) {
    if num.is_empty() {
        return;
    }

    let len = num.len();
    let mut j = len-1;
    let (mut res, mut carry) = num[j].overflowing_add(rhs);
    num[j] = res;

    if j>=1 {
        j -= 1;
        while carry && j>0 {
            (res, carry) = num[j].overflowing_add(1);
            num[j] = res;
            j -= 1;
        }
    }

    if carry {
        res= num[0].wrapping_add(1);
        num[0] = res;
    }        
}

/*  This function performs a modular addition between two numbers represented as byte vectors.
    The reference module is of num1. We expect num1 to be longer or equal to num2. */
pub fn modular_add_vec(num1: &mut Vec<u8>, num2: Vec<u8>) {
    if num1.is_empty() || num2.is_empty() {
        return;
    }

    let len1 = num1.len();
    let len2 = num2.len();
    let mut global_carry= false;
    
    if len2 > len1 {
        return;
    }

    let mut i = len2-1;
    let mut j = len1-1;
    while i > 0 {
        let (res, carry) = num1[j].overflowing_add(num2[i]);
        num1[j] = res;

        if carry {
            let mut num1_copy = num1[..j-1].to_vec();
            let mut num1_rem = num1[j-1..].to_vec();
            modular_add(&mut num1_copy, 1);
            num1.clear();
            num1.append(&mut num1_copy);
            num1.append(&mut num1_rem);
        }

        i -= 1;
        j -= 1;
        global_carry = carry;
    }

    if global_carry {
        let res = num1[0].wrapping_add(num2[0]);
        num1[0] = res;
    }
}

/*  Performs bit a bit XOR between two vectors of the same size. */
pub fn xor_vecs(vec1: &mut Vec<u8>, vec2: &Vec<u8>) {
    if vec1.len() != vec2.len() {
        return;
    }

    for i in 0..vec1.len() {
        vec1[i] = vec1[i] ^ vec2[i];
    }
}