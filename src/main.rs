extern crate edcert;
extern crate edcert_letter;
extern crate edcert_restrevoke;
extern crate edcert_compressor;
extern crate chrono;
extern crate time;
extern crate rustc_serialize;

use edcert::certificate::Certificate;
use edcert::certificate_validator::CertificateValidator;
use edcert::certificate_validator::Revoker;
use edcert::signature::Signature;

fn main() {
    use std::env;

    let mut cmds = env::args();
    let cmd = cmds.nth(1);

    enum Operation {
        Help,
        Info(String),
        Sign(String, String),
        SignMaster(String, String),
        Gen(String, String),
        GenMaster(String),
        Extract(String),
    }

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
    }
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
    use edcert::certificate_validator::CertificateValidator;
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

    let mut mpkfile = File::open(&mpkfile).expect("Failed to open public key file.");
    let mut mpk = [0; 32];
    mpkfile.read_exact(&mut mpk).expect("Failed to read public key");

    if print {
        print!("Loading Certificate {} for inspection...", filename);
    }

    let cv = CertificateValidator::new(&mpk,
                                       RestRevoker::new("https://api.rombie.\
                                                         de/v1/is_revoked?public_key="));
    let cert = CertificateLoader::load_from_file(&filename).expect("Failed to load certificate");

    if print {
        println!(" Done!");
        println!("");
    }

    if !full_info {
        if cert.has_private_key() {
            if print {
                println!("Knows its private key!");
            }
        }

        match cv.is_valid(&cert) {
            Ok(_) => {
                println!("\rValid until {}", cert.expiration_date());
            }
            Err(why) => {
                println!("\rInvalid, because {}", why);
            }
        }
    } else {
        print_cert(&cert, 0, &cv);
    }
}

fn edcert_gen_master(filename: String) {
    use edcert::ed25519::generate_keypair;
    use std::fs::File;
    use std::io::Write;

    print!("Generating master keypair...");
    let (mpk, msk) = generate_keypair();
    println!(" Done!");

    {
        let sk_filename = format!("{}.secretkey", filename);
        print!("Writing secret key to {}...", sk_filename);
        let mut sk_file = File::create(&sk_filename)
                              .expect(&format!("Failed to create secret keyfile {}", &sk_filename));
        sk_file.write(&msk).expect("Failed to write private key");
        println!(" Done!");
    }

    {
        let pk_filename = format!("{}.pub", filename);
        print!("Writing public key to {}...", pk_filename);
        let mut pk_file = File::create(&pk_filename)
                              .expect(&format!("Failed to create public keyfile {}", &pk_filename));
        pk_file.write(&mpk).expect("Failed to write public key");
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

    if expiration_date_str.chars().next().expect("Expiration date empty") == '+' {
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

            if line.len() == 0 {
                break;
            }

            if let Some(pos) = line.find("=") {
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

    if !filename.contains(".") {
        filename = format!("{}.edc", &filename);
    }

    CertificateLoader::save_to_file(&cert, &filename)
        .expect("Failed to write certificate.");
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

fn print<T: std::fmt::Display>(indent: usize, text: T) {
    for _ in 0..indent {
        print!("    ");
    }

    println!("{}", text);
}

fn print_signature<T: Revoker>(signature: &Signature,
                               indent: usize,
                               cv: &CertificateValidator<T>) {
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

fn print_cert<T: Revoker>(cert: &Certificate, indent: usize, cv: &CertificateValidator<T>) {
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
