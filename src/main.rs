//#![windows_subsystem = "windows"] // Disables windows terminal pop-up and std::out

use std::fs;
use std::env;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use faccess::PathExt;
use base64ct::{Base64, Encoding};
use sha2::*;
use sha1::*;
use md5::*;
use rustc_serialize::hex::ToHex;

fn main() {
    let mut hashmode: HashType = HashType::None;
    let mut outputmode: Output = Output::None;
    let mut outputformattingmode: OutputFormatting = OutputFormatting::None;

    let mut arguments: Vec<String> = vec![];
    let mut args_p: Vec<String> = env::args().collect(); // Grab commandline arguments.
    let args = args_p.split_off(1); // Remove the path variable from the arguments.
    for arg in args {
        match arg.to_lowercase().as_str() { // --help string
            "--help" | "-help" => {
                println!("{}", format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",
                "Hasher [64bit] : Created by Melvin M. : Build : (2024-04-24) \n\n",
                "Version: 1.10.1\n\n",
                ">Output Switches<\n",
                "  -rename | -r : Concatonates <md5/sha1/sha256/sha512> onto file name. (default)\n",
                "  -file   | -f : returns <md5/sha1/sha256/sha512> as a file.\n",
                "  -print  | -p : Prints returned <md5/sha1/sha256/sha512> to terminal.\n\n",
                ">Hashing Switches<\n",
                "  -md5    | -m5 : Uses the MD5 Algroithm. (default)\n",
                "  -sha1   | -s1 : Uses the Sha1 Algroithm.\n",
                "  -sha256 | -s2 : Uses the Sha256 Algroithm.\n",
                "  -sha512 | -s5 : Uses the Sha512 Algroithm.\n",
                "  -hex    | -h  : Output in Hexadecimal. (default)\n",
                "  -base64 | -b  : Output in Base64.\n\n",
                ">Other<,,,,\n",
                " --help : returns this.\n",
                " --version | -v : returns the program version"
                ));
                std::process::exit(0); // Exit
            }
            "-md5" | "-m5" => {
                hashmode = HashType::MD5
            },
            "-sha1" | "-s1" => {
                hashmode = HashType::Sha1
            },
            "-sha256" | "s2" => {
                hashmode = HashType::Sha256
            },
            "-sha512" | "-s5" => {
                hashmode = HashType::Sha512
            },
            "-file" | "-f" => {
                outputmode = Output::File
            },
            "-print" | "-p" => {
                outputmode = Output::Print
            }
            "-rename" | "-r" => {
                outputmode = Output::Rename
            },
            "-hex" | "-h" => {
                outputformattingmode = OutputFormatting::Hex
            },
            "-base64" | "-b" => {
                outputformattingmode = OutputFormatting::Base64
            },
            "--version" | "-v" => {
                println!("v1.10.1");
                std::process::exit(0); // Exit
            },
            _ => {
                if Path::new(&arg).readable() {
                    arguments.push(arg); // Is a valid path to read. Push to valid arguments.
                } else {
                    println!("'{}' : Is not a valid path or it is not readable.", arg);
                    std::process::exit(0); // Exit
                }
            }
        }
    }
	// Set defaults if none was chosen.
    match hashmode {
	    HashType::None => {
	    	hashmode = HashType::MD5
	    },
	    _ => {}
	}
    match outputmode { 
        Output::None => {
            outputmode = Output::Rename
        }
        _ => {}
    }

    match outputformattingmode {
        OutputFormatting::None => {
            outputformattingmode = OutputFormatting::Hex
        },
        _ => {}
    }

	// Argument for loop.
    for arg in arguments {
        if Path::readable(Path::new(&arg)) && Path::is_file(Path::new(&arg)) {
            let mut file_name = String::from(Path::file_name(Path::new(&arg)).unwrap().to_str().unwrap()); // Shenanigans to make a string.. 
            let file_extension = String::from(Path::new(&file_name).extension().unwrap_or_default().to_str().unwrap()); // Get file extension if any.
            if file_extension.len() >= 1 {
                file_name = String::from(file_name[0..(file_name.len() - file_extension.len() - 1)].to_owned()); // Remove extension from filename.
            }
            //println!("{}\n{}", file_extension, &file_name); // Debugging
            let hash = hash_file(arg.to_owned(), &hashmode, &outputformattingmode);
            let extension: String = match hashmode {
                HashType::MD5 => {
                    String::from(".md5")
                },
                HashType::Sha1 => {
                    String::from(".sha1")
                },
                HashType::Sha256 => {
                    String::from(".sha256")
                },
                HashType::Sha512 => {
                    String::from(".sha512")
                },
                _ => {String::from(" - how'd you get here??")}
            };
            let hash_file_path = String::from(format!("{}{}", &file_name, extension));
            match outputmode {
                Output::File => {
                    fs::write(Path::new(&hash_file_path), hash.as_bytes()).unwrap();
                },
                Output::Rename => {
                    if file_extension.len() >= 1 {
                        fs::rename(Path::new(&arg), format!("./{}{}.{}", file_name, String::from(format!(" [{}]", hash)), file_extension)).unwrap();
                    } else {
                        fs::rename(Path::new(&arg), format!("./{}{}", file_name, String::from(format!(" [{}]", hash)))).unwrap();
                    }
                },
                Output::Print => {
                    println!("{}", hash);
                },
                _ => {}
            }
        }
    }
}

enum OutputFormatting {
    None,
    Hex,
    Base64
}

enum Output {
    None,
    Print,
    File,
    Rename
}

enum HashType {
    None,
    MD5,
    Sha1,
    Sha256,
    Sha512
}

fn hash_file(path: String, hash_mode: &HashType, outputformatting: &OutputFormatting) -> String {
    let file = fs::File::open(path).unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = [0; 1024];
    match hash_mode {
        HashType::MD5 => {
            let mut hasher = Md5::new();
            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 { break }
                hasher.update(&buffer[..count]);
            }
            match outputformatting {
                OutputFormatting::Hex => {
                    return format!("{}", &hasher.finalize().as_slice().to_hex());
                },
                OutputFormatting::Base64 => {
                    return format!("{}", Base64::encode_string(&hasher.finalize())).to_string();
                },
                _ => { return String::from("No way. Get outta here.") }
            }
        },
        HashType::Sha1 => {
            let mut hasher = Sha1::new();
            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 { break }
                hasher.update(&buffer[..count]);
            }
            match outputformatting {
                OutputFormatting::Hex => {
                    return format!("{}", &hasher.finalize().as_slice().to_hex());
                },
                OutputFormatting::Base64 => {
                    return format!("{}", Base64::encode_string(&hasher.finalize())).to_string();
                },
                _ => { return String::from("No way. Get outta here.") }
            }
        },
        HashType::Sha256 => {
            let mut hasher = Sha256::new();
            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 { break }
                hasher.update(&buffer[..count]);
            }
            match outputformatting {
                OutputFormatting::Hex => {
                    return format!("{}", &hasher.finalize().as_slice().to_hex());
                },
                OutputFormatting::Base64 => {
                    return format!("{}", Base64::encode_string(&hasher.finalize())).to_string();
                },
                _ => { return String::from("No way. Get outta here.") }
            }
        },
        HashType::Sha512 => {
            let mut hasher = Sha512::new();
            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 { break }
                hasher.update(&buffer[..count]);
            }
            match outputformatting {
                OutputFormatting::Hex => {
                    return format!("{}", &hasher.finalize().as_slice().to_hex());
                },
                OutputFormatting::Base64 => {
                    return format!("{}", Base64::encode_string(&hasher.finalize())).to_string();
                },
                _ => { return String::from("No way. Get outta here.") }
            }
        },
        _ => {return String::from("")}
    };
}
