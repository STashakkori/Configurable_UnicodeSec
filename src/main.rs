// Configurable_UnicodeSec
// By: m0nZSt3r, QVLx Labs
       $t@$h, QVLx Labs

extern crate unicode_security;
use unicode_security::GeneralSecurityProfile;
use colored::*;
use std::fs;
use std::env;
use std::fs::File;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::string::ToString;
use unicode_security::general_security_profile::IdentifierType;
use substring::Substring;

fn main()
{
  let args: Vec<String> = env::args().collect();
  
  // Prevent bad arguments from crashing the tool
  if args.len() < 3 {
    println!("Missing arguments.");
    return;
  }
  else if args.len() > 4 {
    println!("Too many arguments.");
    return;
  }

  // "First" arg is path to file to scan
  let in_filename = args[1].trim();

  // Read line, trim out new lines and end lines
  let file_to_check  = match fs::read(in_filename.trim()) {
    Ok(input) => input,
    Err(err) => {
	  println!("***Failed to read the input file. Error : {}", err);
	  return;
    }
  };
  
  // "Second" arg is path to config file
  let conf_filename = args[2].trim();
  
  // Read in cfg file
  let config_file  = match File::open(conf_filename.to_string()) {
    Ok(input) => input,
    Err(err) => {
	  println!("***Failed to Read Config File*** Error : {}", err);
	  return;
    }
  };

  // Create the neccessary hashmaps
  let mut weird_char_counts = HashMap::<u8, u8>::new();    // Map of chars and counts
  let mut weird_char_types = HashMap::<u8, String>::new(); // Map of chars and types
  let mut weird_char_total = 0; 			   // Total count of invalid chars
  let mut custom_list = HashMap::<u8, String>::new();      // Map of white/blacklisted chars


  // Initialize Configuration
  // Loop through custom list and add to hash
  let reader = BufReader::new(config_file);
  for line in reader.lines() {
    let line = match line {
      Ok(l) => l,
      Err(e) => { println!("Lines operation failed: {}", e); return; }
    };
    let yes_or_no = match line.chars().nth(0){
      Some(r) => r,
      None => { println!("Getting y or n from config failed."); return; }
    };
    let custom_char = line.substring(2, line.len());
		
    // match block for if parse to int breaks
    let custom_char_value = match custom_char.parse::<u8>() {
        Ok(input) => input,
        Err(e) => { println!("*Cannot fit cfg value unto u8, Error: {}", e); return; }
    };			
    custom_list.insert(custom_char_value, yes_or_no.to_string());
  }

  // Main Loop
  // Loop through chars(read in as bytes) to check
  for i in &file_to_check {
    let input = *i as char;
    let id_is_allowed = input.identifier_allowed();
    let id_type = match input.identifier_type(){
      Some(m) => m,
      None => { println!("Getting identifier type failed."); return; }
    }; 
    // Check if char mentioned in config file
    let mut custom_list_check = "";
    if custom_list.contains_key(&*i){
      custom_list_check = match custom_list.get(&*i) {
        Some(x) => x,
        None => { println!("Error accessing custom_list. Maybe empty."); return; }
      };
    }

    // Invalid chars
    if !id_is_allowed {
      // If whitelisted, remove it from the weird character maps.
      if custom_list_check.eq("y") || custom_list_check.eq("Y") {
        weird_char_counts.remove(&*i);
        weird_char_types.remove(&*i);
        continue;
      }
      else {
        weird_char_total += 1;
        let count_value = weird_char_counts.entry(*i).or_insert(0);
        *count_value += 1;
        if custom_list_check.eq("n") || custom_list_check.eq("N") {
          weird_char_types.entry(*i).or_insert(String::from("Salvum_cfg"));
        }
        else {
          weird_char_types.entry(*i).or_insert(type_to_string(id_type));
      }
    }
  }
    // If valid
    else{
      // If blacklisted, add to weird maps first time, second time increment count.
      if custom_list_check.eq("n") || custom_list_check.eq("N") {
        println!("i: {}\n", i);
        weird_char_total += 1;
        let count_value = weird_char_counts.entry(*i).or_insert(0);
        *count_value += 1;
        weird_char_types.entry(*i).or_insert(String::from("Salvum_cfg"));
        continue;
      }
    }
  }

  // Determine output filename
  
  // "Third" arg is path to config file
  let out_filename = args[3].trim();
  
  // Print map and write to file
  println!("----------------------------------------");
  println!("     Suspicious characters found");
  println!("========================================");
  println!(" ascii_code => count => info"); 
  println!("========================================");
  let output_file = match File::create(out_filename.trim().to_string()){
    Ok(w) => w,
    Err(e) => { println!("Writing file failed: {}", e); return;}
  };
  let mut out_handle = BufWriter::new(output_file);
  for (key_char, value_count) in weird_char_counts.iter(){
    // Counts
    print!("{: >11} => {: >5} =>", key_char, value_count);
    write!(out_handle, "{: >10} => {: >5} =>", key_char, value_count).expect("unable to write Counts");  
   
    // Types
    let tmp_type = match weird_char_types.get(key_char){
      Some(c) => c,
      None => { println!("Map get operation failed."); return; }
    };
    println!(" {}", tmp_type);
    write!(out_handle, " {}\n", tmp_type).unwrap();
  }
  println!("-----------------------------------------");

  // Print count
  println!("{} {} {} {}", "Found".red().bold(), weird_char_total, "invalid characters. Report written to".red().bold(), out_filename.to_string());
}

fn type_to_string(type_enum: IdentifierType) -> String
{
    match type_enum
    {
        // Not allowed
        IdentifierType::Not_Character => return String::from("Not_Character"),
        IdentifierType::Deprecated => return String::from("Deprecated"),
        IdentifierType::Default_Ignorable => return String::from("Default_Ignorable"),
        IdentifierType::Not_NFKC => return String::from("Not_NFKC"),
        IdentifierType::Not_XID => return String::from("Not_XID"),
        IdentifierType::Exclusion => return String::from("Exclusion"),
        IdentifierType::Obsolete => return String::from("Obsolete"),
        IdentifierType::Technical => return String::from("Technical"),
        IdentifierType::Uncommon_Use => return String::from("Uncommon_Use"),
        IdentifierType::Limited_Use => return String::from("Limited_Use"),
        // Allowed
        IdentifierType::Inclusion => return String::from("Inclusion"),
        IdentifierType::Recommended => return String::from("Recommended")
    }
}
