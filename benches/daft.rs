use std::collections::HashMap;

use criterion::{Criterion, black_box, BenchmarkId, criterion_group, criterion_main};
use daft::abe::Plaintext;
use daft::daft::daft::{sender_key_gen, authority_key_gen, prepare_sending, authenticate_received_file};
use std::time::Instant;
use std::fs::File;


static MB: usize = 1000000;
static START : usize = 50;
static END : usize = 500;
static STEP : usize = 50;

#[allow(dead_code)]
pub fn daft_file_transfer(c : &mut Criterion) {
    let (_, signing_key ) = sender_key_gen();
    let (apk, _) = authority_key_gen();

    

    let mut group = c.benchmark_group("file-transfer");
    group.sample_size(10);
    for size in ( START..END ).step_by(STEP) {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            // initiate the file 
            let plaintext = Plaintext::from(vec![0; size * MB]);

            b.iter(|| {
                let access_policy =  String::from(r#""A" or "B""#);
                let response = prepare_sending(
                    &signing_key, 
                    &apk, 
                    access_policy, 
                    &plaintext
                );
                black_box(response.is_ok());

            });
        });
    }
    
    group.finish();
}

#[allow(dead_code)]
pub fn daft_file_reception(c : &mut Criterion) {
    let (verification_key, signing_key ) = sender_key_gen();
    let (apk, ask) = authority_key_gen();
    // generate the secret key for the receiver
    let attr = vec!["A".to_string()];
    let sk = ask.gen_secret_key(attr);


    let mut group = c.benchmark_group("file-reception");
    group.sample_size(10);
    for size in ( START..END ).step_by(STEP) {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            // initiate the file 
            let plaintext = Plaintext::from(vec![0; size * MB]);
            let access_policy =  String::from(r#""A" or "B""#);
                let response = prepare_sending(
                    &signing_key, 
                    &apk, 
                    access_policy, 
                    &plaintext
                );
            let (link, signature, ciphertext) = response.unwrap();

            b.iter(|| {
                
                let plaintext_response = authenticate_received_file(
                    &verification_key, 
                    &sk, 
                    &apk, 
                    &signature, 
                    &link, 
                    &ciphertext
                );
                black_box(plaintext_response.is_ok());

            });
        });
    }
    group.finish();
}


#[allow(dead_code)]
pub fn daft_benchmarks_into_csv(_ : &mut Criterion) {
    // create the local variables inside the programm
    let mut record_execution_time = HashMap::new();
    let mut record_communication_size = HashMap::new();

    // we compute the execution time for the given number of iterations
    static NB_ITER : usize = 100;

    let (verification_key, signing_key ) = sender_key_gen();
    let (apk, ask) = authority_key_gen();
    // generate the secret key for the receiver
    let attr = vec!["A".to_string()];
    let sk = ask.gen_secret_key(attr);

   

    let bar = indicatif::ProgressBar::new(((END - START) / STEP) as u64);
    for size in ( START..END ).step_by(STEP) {
        bar.inc(1);

        // initiate the file 
        let plaintext = Plaintext::from(vec![0; size * MB]);
        assert_eq!(size * MB, plaintext.len());
        
        for index in 0..NB_ITER {
          
            let access_policy =  String::from(r#""A" or "B""#);
            let (response, send_execution_time) = {
                let start = Instant::now();
                let response = prepare_sending(
                    &signing_key, 
                    &apk, 
                    access_policy, 
                    &plaintext
                );
                (response.unwrap(), start.elapsed())
            }; 

            let (link, signature, ciphertext) = response;
            let (_, receive_execution_time) = {
                let start = Instant::now();
                let plaintext_response = authenticate_received_file(
                    &verification_key, 
                    &sk, 
                    &apk, 
                    &signature, 
                    &link, 
                    &ciphertext
                );
                (plaintext_response.unwrap(), start.elapsed())
            };

            match record_execution_time.get(&size) {
                Some( (a, b) ) => record_execution_time.insert(
                    size, ( a + send_execution_time.as_millis(), b + receive_execution_time.as_millis() )
                ),
                None => record_execution_time.insert(
                    size, ( send_execution_time.as_millis(), receive_execution_time.as_millis() )
                ),
            };

            if index == 0 {
                let naive_size = ciphertext.len();
                let daft_users = signature.to_vec().len() + link.len();
                let daft_storage = naive_size;
                record_communication_size.insert(
                    size, 
                    (naive_size, daft_users, daft_storage)
                );
            }
        }
    }
    bar.finish();

    // export the result into a csv file
    let file = File::create("execution_time.csv").unwrap();
    let mut wtr = csv::Writer::from_writer(file);
    let _ = wtr.write_record(&["file_size", "send", "receive"]);
    for (file_size, (send_execution_time, receive_execution_time)) in record_execution_time.iter() {
        let _ = wtr.write_record(&[
            file_size, 
            &(*send_execution_time as usize / NB_ITER),
            &(*receive_execution_time as usize / NB_ITER)
        ].map(|n| n.to_string()));
    }

    let file = File::create("communication_size.csv").unwrap();
    let mut wtr = csv::Writer::from_writer(file);
    let _ = wtr.write_record(&["file_size", "naive", "daft_users", "daft_storage"]);
    for (file_size, (naive, daft_users, daft_storage)) in record_communication_size.iter() {
        let _ = wtr.write_record(&[
            file_size, 
            naive,
            daft_users,
            daft_storage
        ].map(|n| n.to_string()));
    }
}


criterion_group!(
    name = daft;
    config = Criterion::default();
    targets = 
    daft_file_transfer, daft_file_reception
        
);


criterion_main!(daft);