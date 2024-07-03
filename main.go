package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

type user_data struct {
	Login    string
	Password string
}

func aes_encrypt(msg string, key string) (string, error) {
	var block, err_cipher = aes.NewCipher([]byte(key))

	if err_cipher != nil {
		return "", err_cipher
	}

	var cipher_text = make([]byte, aes.BlockSize+len([]byte(msg)))
	var iv = cipher_text[:aes.BlockSize]
	var _, err_read = io.ReadFull(rand.Reader, iv)

	if err_read != nil {
		return "", err_read
	}

	var stream = cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipher_text[aes.BlockSize:], []byte(msg))

	return base64.StdEncoding.EncodeToString(cipher_text), nil
}

func aes_decrypt(msg string, key string) (string, error) {
	var cipher_text, err_b64 = base64.StdEncoding.DecodeString(msg)

	if err_b64 != nil {
		return "", err_b64
	}

	var block, err_cipher = aes.NewCipher([]byte(key))

	if err_cipher != nil {
		return "", err_cipher
	}

	if len(cipher_text) < aes.BlockSize {
		return "", errors.New("invalid block size")
	}

	var iv = cipher_text[:aes.BlockSize]
	cipher_text = cipher_text[aes.BlockSize:]

	var stream = cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipher_text, cipher_text)

	return string(cipher_text), nil
}

func json_to_file(name string, data string) error {
	if _, err_exists := os.Stat("/data"); os.IsNotExist(err_exists) {
		os.Mkdir("data", os.ModePerm)
	}

	var err_write = os.WriteFile("data\\"+name+".json", []byte(data), os.ModePerm)

	if err_write != nil {
		return err_write
	}

	return nil
}

func file_to_json(name string) (user_data, error) {
	body, err_read := os.ReadFile("data\\" + name + ".json")

	if err_read != nil {
		return user_data{}, err_read
	}

	var temp = user_data{}
	var err_json = json.Unmarshal([]byte(body), &temp)

	if err_json != nil {
		return user_data{}, err_json
	}

	return temp, nil
}

func save_user_data(description string, login string, password string, key string) error {
	var password_enc, err_enc = aes_encrypt(password, key)

	if err_enc != nil {
		return err_enc
	}

	var temp = user_data{
		Login:    login,
		Password: password_enc,
	}

	var json_data, err_json = json.MarshalIndent(temp, "", "    ")

	if err_json != nil {
		return err_json
	}

	var err_file = json_to_file(description, string(json_data))

	if err_file != nil {
		return err_file
	}

	return nil
}

func clear() {
	if runtime.GOOS == "windows" {
		var cmd = exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		var cmd = exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func main() {
	fmt.Printf("1. Save\n2. Read\n-> ")

	var main int
	fmt.Scan(&main)

	if main == 1 {
		clear()
		var desc, log, pass, key string

		fmt.Printf("Description\n-> ")
		fmt.Scan(&desc)
		fmt.Printf("Login\n-> ")
		fmt.Scan(&log)
		fmt.Printf("Password\n-> ")
		fmt.Scan(&pass)
		fmt.Printf("Encryption Key, Must Be 16-Bits Long!\n-> ")
		fmt.Scan(&key)

		save_user_data(desc, log, pass, key)

		fmt.Printf("Data saved successfully!")
		fmt.Scanln()
		return
	} else if main == 2 {
		clear()
		var desc, key string

		fmt.Printf("Description\n-> ")
		fmt.Scan(&desc)
		fmt.Printf("Decryption Key\n-> ")
		fmt.Scan(&key)

		var data, err_read = file_to_json(desc)

		if err_read != nil {
			fmt.Printf("reading json from file failed: %v", err_read)
			return
		}

		clear()

		var pass_decrypt, err_decrypt = aes_decrypt(data.Password, key)

		if err_decrypt != nil {
			fmt.Printf("password decryption failed: %v", err_decrypt)
			return
		}

		fmt.Printf("Login: %v\n", data.Login)
		fmt.Printf("Password: %v\n", pass_decrypt)
		fmt.Scanln()
		return
	} else {
		fmt.Printf("not a valid option")
		fmt.Scanln()
		return
	}
}
