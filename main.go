package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type user_data struct {
	Login    string
	Password string
}

func aes_encrypt(msg string, key string) (string, error) {
	var block, err_cipher = aes.NewCipher([]byte(key))

	if err_cipher != nil {
		return "", fmt.Errorf("creating new cipher failed: %v", err_cipher)
	}

	var cipher_text = make([]byte, aes.BlockSize+len([]byte(msg)))
	var iv = cipher_text[:aes.BlockSize]
	var _, err_read = io.ReadFull(rand.Reader, iv)

	if err_read != nil {
		return "", fmt.Errorf("encryption failed: %v", err_read)
	}

	var stream = cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipher_text[aes.BlockSize:], []byte(msg))

	return base64.StdEncoding.EncodeToString(cipher_text), nil
}

func aes_decrypt(msg string, key string) (string, error) {
	var cipher_text, err_b64 = base64.StdEncoding.DecodeString(msg)

	if err_b64 != nil {
		return "", fmt.Errorf("decoding base64 failed: %v", err_b64)
	}

	var block, err_cipher = aes.NewCipher([]byte(key))

	if err_cipher != nil {
		return "", fmt.Errorf("creating new cipher failed: %v", err_cipher)
	}

	if len(cipher_text) < aes.BlockSize {
		return "", fmt.Errorf("invalid block size")
	}

	var iv = cipher_text[:aes.BlockSize]
	cipher_text = cipher_text[aes.BlockSize:]

	var stream = cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipher_text, cipher_text)

	return string(cipher_text), nil
}

func json_to_file(name string, data string) error {
	var home, err_home = os.UserHomeDir()

	if err_home != nil {
		return fmt.Errorf("getting users home directory failed: %v", err_home)
	}

	var err_folder = os.Mkdir(home+"\\pwd", os.ModePerm)

	if err_folder != nil {
		return fmt.Errorf("getting users home directory failed: %v", err_folder)
	}

	var err_write = os.WriteFile(home+"\\pwd\\"+name+".json", []byte(data), os.ModePerm)

	if err_write != nil {
		return fmt.Errorf("writing json to file failed: %v", err_write)
	}

	return nil
}

func cmd_in_int(msg string) int {
	fmt.Print(msg)
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')

	if err != nil {
		fmt.Printf("reading input failed: %v", err)
		return 0
	}

	strings.TrimSuffix(input, "\n")

	var conv, err_conv = strconv.Atoi(input)

	if err_conv != nil {
		fmt.Printf("type conversion input: %v", err)
		return 0
	}

	return conv
}

func cmd_in_string(msg string) string {
	fmt.Print(msg)
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')

	if err != nil {
		fmt.Printf("reading input failed: %v", err)
		return ""
	}

	strings.TrimSuffix(input, "\n")
	return input
}

func save_user_data(description string, login string, password string, key string) error {
	var password_enc, err_enc = aes_encrypt(password, key)

	if err_enc != nil {
		return fmt.Errorf("password encryption failed: %v", err_enc)
	}

	var temp = user_data{
		Login:    login,
		Password: password_enc,
	}

	var json_data, err_json = json.MarshalIndent(temp, "", "    ")

	if err_json != nil {
		return fmt.Errorf("json failed: %v", err_json)
	}

	var err_file = json_to_file(description, string(json_data))

	if err_file != nil {
		return fmt.Errorf("writing json to file failed: %v", err_file)
	}

	return nil
}

func pause() error {
	var buf = make([]byte, 1)

	for {
		var data, err_read = os.Stdin.Read(buf)

		if data != 1 {
			return err_read
		}
		if buf[0] == '\n' {
			break
		}
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

func main() { // TODO: FIX FAST
	fmt.Printf("1. Save\n2. Read\n")

	var input = cmd_in_string("Option: ")

	fmt.Print(input)

	if strings.Compare(input, "1") == 0 {
		clear()
		var description = cmd_in_string("Description: ")
		var login = cmd_in_string("\nLogin: ")
		var password = cmd_in_string("\nPassword: ")
		var key = cmd_in_string("\nEncryption Key (Save This!): ")

		save_user_data(description, login, password, key)

		var home, err_home = os.UserHomeDir()

		if err_home != nil {
			fmt.Printf("getting users home directory failed: %v", err_home)
			return
		}

		fmt.Printf("Succesfully saved data in: %v", home+"\\pwd")
		pause()
	} else if strings.Compare(input, "2") == 0 {
		pause()
	} else {
		fmt.Printf("not a valid option\n")
		pause()
		return
	}
}
