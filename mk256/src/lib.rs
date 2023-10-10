use sha2::{Digest, Sha512_256};
use tiger::{Tiger2};
use rayon::join;


pub fn mk256( data : &[u8] ) -> [u8; 32] { 
    // handles 1MB of data without recursion
    if data.len() <= 1000000 { 
        let mut cipher = Tiger2::new();
        cipher.update(data);
        let tiger_digest  = cipher.finalize();

        let mut cipher = Sha512_256::new();
        cipher.update( tiger_digest );
        return cipher.finalize().into()
    }

    // split the data and compute the hash of each part in parallel
    let mid = data.len() / 2;
    let (left, right) = data.split_at(mid);
    let (left_hash, right_hash) = join(
        || mk256(left), 
        || mk256(right)
    );

    // compute the hash of both data
    let mut cipher = Sha512_256::new();
    cipher.update( left_hash );
    cipher.update( right_hash );
    cipher.finalize().into()
}



#[cfg(test)]
mod tests {
    use std::time::Instant;
    use crate::mk256;

    #[test]
    pub fn execution_time() {
        for size in (50..500).step_by(50) {
            let data = vec![0; size * 1000000];
            
            let start = Instant::now();
            let hash = mk256(&data);
            let duration = start.elapsed().as_millis();
    
          
    
            println!("{}: merkle tree : {}ms", size, duration);
            let hash2 = mk256(&data);
            assert_eq!(hash, hash2);
        }
    }
}