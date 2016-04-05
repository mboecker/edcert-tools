extern crate edcert;
extern crate edcert_letter;
extern crate edcert_restrevoke;
extern crate edcert_compressor;
extern crate chrono;
extern crate time;
extern crate rustc_serialize;
extern crate threadpool;
extern crate num_cpus;

use edcert::certificate::Certificate;
use edcert::signature::Signature;

use edcert::validator::Validator;
use edcert::trust_validator::TrustValidator;
use edcert::revoker::Revoker;

fn main() {
    use std::env;

    enum Operation {
        Help,
        Info(String),
        Sign(String, String),
        SignMaster(String, String),
        Gen(String, String),
        GenMaster(String),
        Extract(String),
        LetterSign(String, Vec<String>),
        LetterVerify(String, String),
    }

    let mut cmds = env::args();
    let cmd = cmds.nth(1);

    let mut op = Operation::Help;

    if cmd.is_some() {
        let cmd = cmd.unwrap();

        op = match &cmd[..] {
            "help" => Operation::Help,
            "info" => {
                let arg = cmds.nth(0);
                if arg.is_some() {
                    Operation::Info(arg.unwrap())
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            "gen-master" => {
                let arg = cmds.nth(0);
                if arg.is_some() {
                    Operation::GenMaster(arg.unwrap())
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            "gen" => {
                let arg = cmds.nth(0);
                let arg2 = cmds.nth(0);
                if arg.is_some() && arg2.is_some() {
                    Operation::Gen(arg.unwrap(), arg2.unwrap())
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            "sign" => {
                let arg = cmds.nth(0);
                let arg2 = cmds.nth(0);
                if arg.is_some() && arg2.is_some() {
                    Operation::Sign(arg.unwrap(), arg2.unwrap())
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            "sign-master" => {
                let arg = cmds.nth(0);
                let arg2 = cmds.nth(0);
                if arg.is_some() && arg2.is_some() {
                    Operation::SignMaster(arg.unwrap(), arg2.unwrap())
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            "extract" => {
                let arg = cmds.nth(0);
                if arg.is_some() {
                    Operation::Extract(arg.unwrap())
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            "letter-sign" => {
                let arg = cmds.nth(0);
                let mut vec = Vec::new();

                for key in cmds {
                    use std::fs::File;

                    if let Ok(x) = File::open(&key) {
                        if let Ok(x) = x.metadata() {
                            if x.is_file() {
                                vec.push(key.to_string());
                            }
                        }
                    }
                }

                if arg.is_some() {
                    Operation::LetterSign(arg.unwrap(), vec)
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            "letter-verify" => {
                let arg = cmds.nth(0);
                let arg2 = cmds.nth(0);
                if arg.is_some() && arg2.is_some() {
                    Operation::LetterVerify(arg.unwrap(), arg2.unwrap())
                } else {
                    missing_option();
                    Operation::Help
                }
            }
            x => {
                println!("Error: Unknown command: {}", x);
                println!("");
                Operation::Help
            }
        };
    }

    match op {
        Operation::Help => edcert_help(),
        Operation::Info(filename) => edcert_info(filename),
        Operation::GenMaster(filename) => edcert_gen_master(filename),
        Operation::Gen(filename, expiration_date) => edcert_gen_cert(filename, expiration_date),
        Operation::SignMaster(master_filename, certificate_filename) => {
            edcert_sign_master(master_filename, certificate_filename)
        }
        Operation::Sign(parent_filename, certificate_filename) => {
            edcert_sign_cert(parent_filename, certificate_filename)
        }
        Operation::Extract(filename) => edcert_extract(filename),
        Operation::LetterSign(certificate, letter) => edcert_sign_letter(certificate, &letter),
        Operation::LetterVerify(certificate, letter) => edcert_verify_letter(certificate, letter),
    };
}

#[derive(PartialEq)]
enum Flag {
    Quiet,
    FullInfo,
    UseMasterFile(String),
}

fn get_flags() -> Vec<Flag> {
    use std::env;

    let mut flags = vec![];

    let iter = env::args();

    for flag in iter {
        match flag.as_str() {
            "-q" | "--quiet" => flags.push(Flag::Quiet),
            "--full" => flags.push(Flag::FullInfo),
            "--master" => {
                flags.push(Flag::UseMasterFile("lel".to_string()));
            }
            _ => {}
        };
    }

    flags
}

fn missing_option() {
    println!("Error: Missing option for command.");
    println!("");
}

fn edcert_help() {
    println!("Edcert's certificate utility");
    println!("");
    println!("Usage:");
    println!("    edcert <command> [<args>...]");
    println!("");
    println!("where OPERATION is one of ...");
    println!("    help \t\t\t\t\t\t Show a help of this program.");
    println!("    info <filename> \t\t\t\t\t Show information about a certificate.");
    println!("    gen-master <output filename>  \t\t\t Generate a master keypair.");
    println!("    gen <output filename> <expiration date> \t\t\t\t Generate a random certificate \
              from a secure source.");
    println!("    sign-master <certificate> <private keyfile> \t Sign a certificate with a \
              master private key.");
    println!("    sign <signee> <signer> \t\t\t\t Sign a certificate with a certificate.");
    println!("    extract <filename> \t\t\t Extract the encoded certificate to JSON.");
    println!("");
}

fn edcert_info(filename: String) {
    use edcert_compressor::certificate_loader::CertificateLoader;
    use edcert::trust_validator::TrustValidator;
    use edcert_restrevoke::restrevoker::RestRevoker;
    use std::fs::File;
    use std::io::Read;

    let mut print = true;
    let mut full_info = false;
    let mut mpkfile = "master.pub".to_string();

    for flag in get_flags() {
        match flag {
            Flag::Quiet => {
                print = false;
            }
            Flag::FullInfo => {
                full_info = true;
            }
            Flag::UseMasterFile(arg) => {
                mpkfile = arg;
            }
        }
    }

    if print {
        println!("Loading public key from {}", &mpkfile);
        println!("Use -m <keyfile> to override");
    }

    let mut mpkfile = match File::open(&mpkfile) {
        Err(_) => {
            println!("Failed to open public key file.");
            return;
        }
        Ok(x) => x,
    };
    let mut mpk = [0; 32];
    match mpkfile.read_exact(&mut mpk) {
        Err(_) => {
            println!("Failed to read public key");
            return;
        }
        Ok(x) => x,
    };

    if print {
        print!("Loading Certificate {} for inspection...", filename);
    }

    let cv = TrustValidator::new(&mpk,
                                 RestRevoker::new("https://api.rombie.\
                                                   de/v1/is_revoked?public_key="));
    let cert = CertificateLoader::load_from_file(&filename);

    let cert = match cert {
        Err(x) => {
            if print {
                println!("Failed!");
            }
            println!("{}", x);
            return;
        }
        Ok(x) => x,
    };

    if print {
        println!(" Done!");
        println!("");
    }

    if full_info {
        print_cert(&cert, 0, &cv);
    }
    else {
        if cert.has_private_key() && print {
            println!("Knows its private key!");
        }

        match cv.is_valid(&cert) {
            Ok(_) => {
                println!("\rValid until {}", cert.expiration_date());
            }
            Err(why) => {
                println!("\rInvalid, because {}", why);
            }
        }
    }
}

fn edcert_gen_master(filename: String) {
    use edcert::ed25519::generate_keypair;
    use std::fs::File;
    use std::io::Write;

    print!("Generating master keypair...");
    let (mpubkey, mseckey) = generate_keypair();
    println!(" Done!");

    {
        let sk_filename = format!("{}.secretkey", filename);
        print!("Writing secret key to {}...", sk_filename);
        let mut sk_file = match File::create(&sk_filename) {
            Err(_) => {
                println!("Failed to create secret keyfile {}", &sk_filename);
                return;
            }
            Ok(x) => x,
        };
        match sk_file.write(&mseckey) {
            Err(_) => {
                println!("Failed to write private key");
                return;
            }
            Ok(x) => x,
        };
        println!(" Done!");
    }

    {
        let pk_filename = format!("{}.pub", filename);
        print!("Writing public key to {}...", pk_filename);
        let mut pk_file = match File::create(&pk_filename) {
            Err(_) => {
                println!("Failed to create public keyfile {}", &pk_filename);
                return;
            }
            Ok(x) => x,
        };
        match pk_file.write(&mpubkey) {
            Err(_) => {
                println!("Failed to write public key");
                return;
            }
            Ok(x) => x,
        };

        println!(" Done!");
    }
}

fn edcert_gen_cert(mut filename: String, expiration_date_str: String) {
    use edcert::certificate::Certificate;
    use edcert_compressor::certificate_loader::CertificateLoader;
    use edcert::meta::Meta;
    use chrono::UTC;
    use chrono::DateTime;
    use chrono::Timelike;
    use chrono::Duration;
    use std::io;

    print!("Parsing expiration date...");

    let mut expiration_date: DateTime<UTC>;

    if expiration_date_str.is_empty() {
        println!("Expiration date is empty");
        return;
    }

    if expiration_date_str.chars().next().unwrap() == '+' {
        expiration_date = UTC::now();
        let mut iter = expiration_date_str.chars();
        iter.next();

        let mut num_acc: i64 = 0;

        for dchar in iter {
            if dchar.is_digit(10) {
                num_acc = num_acc * 10 + (dchar.to_digit(10).unwrap()) as i64;
            } else {

                let mut add = |dur: Duration| {
                    match expiration_date.checked_add(dur) {
                        Some(date) => {
                            expiration_date = date;
                        }
                        None => {
                            println!(" Failed!");
                            println!("You can use s,m,h,d,w,y as duration modifiers");
                            println!("Example: +10m5s");
                            return;
                        }
                    }
                };

                add(match dchar {
                    's' => Duration::seconds(num_acc as i64),
                    'm' => Duration::minutes(num_acc as i64),
                    'h' => Duration::hours(num_acc as i64),
                    'd' => Duration::days(num_acc as i64),
                    'w' => Duration::weeks(num_acc as i64),
                    _ => {
                        println!(" Failed!");
                        println!("You can use s,m,h,d,w as duration modifiers");
                        println!("Example: +10m5s");
                        return;
                    }
                });

                num_acc = 0;
            }
        }
        expiration_date = expiration_date.with_nanosecond(0)
                                         .expect("Failed to set nanoseconds to 0");
    } else {
        match DateTime::parse_from_rfc3339(&expiration_date_str) {
            Err(_) => {
                println!(" Failed!");
                println!("Please give the expiration date in RFC 3339 encoded form.");
                println!("Example: {}",
                         UTC::now().with_nanosecond(0).unwrap().to_rfc3339());
                return;
            }
            Ok(date) => {
                expiration_date = date.with_timezone(&UTC);
            }
        };
    }

    println!(" Done!");

    println!("You can now enter metadata associated with your certificate. Common ones are \
              'name' or 'use-for'");
    println!("Enter like this: <key>=<value>");
    println!("Empty line when you're done.");

    let mut meta = Meta::new_empty();

    let stdio = io::stdin();
    let mut line = String::new();
    while stdio.read_line(&mut line).is_ok() {
        {
            let line = line.trim();

            if line.is_empty() {
                break;
            }

            if let Some(pos) = line.find('=') {
                let (mut key, mut value) = line.split_at(pos);
                value = value[1..].trim();
                key = key.trim();

                println!("Key: {}, Value: {}", key, value);

                meta.set(key, value);
            } else {
                println!("Error. Please enter metadata like this: name=value");
            }
        }
        line = String::new();
    }

    print!("Generating random certificate...");
    let cert = Certificate::generate_random(meta, expiration_date);
    println!(" Done!");

    if cert.is_expired() {
        println!("Warning: The expiration date you entered is in the past. The certificate will \
                  not be valid.");
    }

    if !filename.contains('.') {
        filename = format!("{}.edc", &filename);
    }

    if let Err(_) = CertificateLoader::save_to_file(&cert, &filename) {
        println!("Failed to write certificate.");
        return;
    };
}

fn edcert_sign_master(certificate_filename: String, master_filename: String) {
    use edcert_compressor::certificate_loader::CertificateLoader;
    use std::fs::File;
    use std::io::Read;

    println!("Loading public key from {}", &master_filename);
    println!("Use -m <keyfile> to override");

    let mut mskfile = File::open(&master_filename).expect("Failed to open private key file.");
    let mut msk = [0; 64];
    mskfile.read_exact(&mut msk).expect("Failed to read private key");

    print!("Loading Certificate {} for signing...",
           certificate_filename);

    let mut cert = CertificateLoader::load_from_file(&certificate_filename)
                       .expect("Failed to load certificate");

    println!(" Done!");

    cert.sign_with_master(&msk);

    CertificateLoader::save_to_file(&cert, &certificate_filename)
        .expect("Failed to write signed file.");
}

fn edcert_sign_cert(certificate_filename: String, parent_filename: String) {
    use edcert_compressor::certificate_loader::CertificateLoader;

    let mut cert = CertificateLoader::load_from_file(&certificate_filename)
                       .expect("Failed to load certificate");
    let parent = CertificateLoader::load_from_file(&parent_filename)
                     .expect("Failed to load parent certificate");
    parent.sign_certificate(&mut cert).expect("Failed to sign certificate.");
    CertificateLoader::save_to_file(&cert, &certificate_filename)
        .expect("Failed to write certificate");
}

fn edcert_extract(filename: String) {
    use rustc_serialize::json;
    use edcert_compressor::certificate_loader::CertificateLoader;

    let cert = CertificateLoader::load_from_file(&filename).expect("Failed to load certificate");
    println!("{}", json::as_pretty_json(&cert));
}

fn to_bytestr(vec: &[u8]) -> String {
    let bytestr: Vec<String> = vec.iter().map(|b| format!("{:02X}", b)).collect();
    bytestr.join("")
}

fn from_bytestr(vec: &str) -> Option<Vec<u8>> {
    use rustc_serialize::hex::FromHex;
    match vec.from_hex() {
        Ok(x) => Some(x),
        Err(_) => None,
    }
}

fn print<T: std::fmt::Display>(indent: usize, text: T) {
    for _ in 0..indent {
        print!("    ");
    }

    println!("{}", text);
}

fn print_signature<R: Revoker>(signature: &Signature, indent: usize, cv: &TrustValidator<R>) {
    print(indent, "Signature:");

    print(indent + 1,
          format!("Hash: {}", to_bytestr(&signature.hash()[0..64])));

    print(indent + 1, "Signed by:");

    if signature.is_signed_by_master() {
        print(indent + 2, "Master Key");
    } else {
        print_cert(signature.parent().unwrap(), indent + 2, cv);
    }
}

fn print_cert<R: Revoker>(cert: &Certificate, indent: usize, cv: &TrustValidator<R>) {
    print(indent, "Certificate");
    for (key, value) in cert.meta().values() {
        let tabs = if key.len() < 7 {
            "\t\t"
        } else {
            "\t"
        };
        print(indent, format!("{}:{}{}", key, tabs, value));
    }
    print(indent,
          format!("Public Key:\t{}", to_bytestr(cert.public_key())));
    print(indent,
          format!("Revoked:\t{}", cv.is_revoked(cert).is_err()));
    print(indent, format!("Expires:\t{}", cert.expiration_date()));
    print(indent, format!("Valid:\t\t{}", cv.is_valid(cert).is_ok()));

    if cert.is_signed() {
        print_signature(cert.signature().as_ref().unwrap(), indent, cv);
    } else {
        print(indent, "Not signed");
    }
}

fn edcert_sign_letter(certificate_filename: String, letter_filenames: &[String]) {
    use std::io::Read;
    use std::fs::File;
    use std::sync::mpsc;
    use std::sync::Arc;
    use edcert_compressor::certificate_loader::CertificateLoader;
    use threadpool::ThreadPool;

    let cert = match CertificateLoader::load_from_file(&certificate_filename) {
        Err(x) => {
            println!("Failed to load certificate!");
            println!("{}", x);
            return;
        }
        Ok(x) => x,
    };

    if letter_filenames.is_empty() {
        let mut content = Vec::new();

        let mut letter = std::io::stdin();

        match letter.read_to_end(&mut content) {
            Ok(x) => x,
            _ => {
                println!("Failed to read letter content!");
                return;
            }
        };

        let sig = cert.sign(&content).expect("Failed to sign content.");

        println!("{}  -", to_bytestr(&sig));
    } else {
        let pool = ThreadPool::new(num_cpus::get());
        let cert = Arc::new(cert);
        let (sendr, recvr) = mpsc::channel();

        for letter_filename in letter_filenames {

            let letter_filename = letter_filename.to_owned();
            let cert = cert.clone();
            let sendr = sendr.clone();

            pool.execute(move || {
                let mut content = Vec::new();

                let mut letter = match File::open(&letter_filename) {
                    Err(x) => {
                        println!("Failed to open letter!");
                        println!("{}", x);
                        return;
                    }
                    Ok(x) => x,
                };

                match letter.read_to_end(&mut content) {
                    Ok(x) => x,
                    _ => {
                        println!("Failed to read letter content!");
                        return;
                    }
                };

                let sig = cert.sign(&content).expect("Failed to sign content.");

                sendr.send(format!("{}  {}", to_bytestr(&sig), letter_filename)).unwrap();
            });
        }

        for _ in 0..letter_filenames.len() {
            println!("{}", recvr.recv().unwrap());
        }
    }
}

fn edcert_verify_letter(certificate_filename: String, letter_filename: String) {
    use std::io::Read;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::fs::File;
    use std::sync::mpsc;
    use std::sync::Arc;
    use edcert_compressor::certificate_loader::CertificateLoader;
    use threadpool::ThreadPool;

    enum Status {
        Valid,
        Invalid,
        Failed,
    }

    let cert = match CertificateLoader::load_from_file(&certificate_filename) {
        Err(x) => {
            println!("Failed to load certificate!");
            println!("{}", x);
            return;
        }
        Ok(x) => x,
    };

    let cert = Arc::new(cert);

    let letter = match File::open(&letter_filename) {
        Err(x) => {
            println!("Failed to open letter!");
            println!("{}", x);
            return;
        }
        Ok(x) => x,
    };

    let letter = BufReader::new(letter);

    let (sendr, recvr) = mpsc::channel();
    let pool = ThreadPool::new(num_cpus::get());

    let mut num_all = 0;

    for line in letter.lines() {
        let sendr = sendr.clone();
        let cert = cert.clone();
        num_all += 1;

        pool.execute(move || {
            let line = line.expect("Failed to read line");
            let (hash, filename) = line.split_at(128);
            let hash = hash.trim();

            let hash = match from_bytestr(hash) {
                Some(x) => x,
                None => {
                    println!("{}\t{}", "FAILED", filename);
                    sendr.send(Status::Failed).unwrap();
                    return;
                }
            };

            let filename = filename.trim();

            let mut file = match File::open(filename) {
                Ok(x) => x,
                _ => {
                    println!("{}\t{}", "FAILED", filename);
                    sendr.send(Status::Failed).unwrap();
                    return;
                }
            };

            let mut content = Vec::<u8>::new();

            match file.read_to_end(&mut content) {
                Ok(_) => {}
                Err(_) => {
                    println!("{}\t{}", "FAILED", filename);
                    sendr.send(Status::Failed).unwrap();
                    return;
                }
            };

            let valid = cert.verify(&content, &hash);

            if valid {
                println!("{}\t{}", "VALID", filename);
            } else {
                println!("{}\t{}", "INVALID", filename);
            }

            if valid {
                sendr.send(Status::Valid).unwrap();
            } else {
                sendr.send(Status::Invalid).unwrap();
            }
        });
    }

    let mut num_valid = 0;
    let mut num_invalid = 0;
    let mut num_failed = 0;

    for _ in 0..num_all {
        let status = recvr.recv().expect("Failed to recv data from channel");
        match status {
            Status::Valid => {
                num_valid += 1;
            }
            Status::Invalid => {
                num_invalid += 1;
            }
            Status::Failed => {
                num_failed += 1;
            }
        }
    }

    println!("Statistics: ");
    println!("Valid: {}/{} ({:.2}%)",
             num_valid,
             num_all,
             num_valid as f64 / num_all as f64 * 100.0);
    println!("Invalid: {}/{} ({:.2}%)",
             num_invalid,
             num_all,
             num_invalid as f64 / num_all as f64 * 100.0);
    println!("Failed: {}/{} ({:.2}%)",
             num_failed,
             num_all,
             num_failed as f64 / num_all as f64 * 100.0);
}
