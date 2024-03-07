/*
 *  Copyright (c) 2024 Thales Group Limited. All Rights Reserved.
 *  This software is the confidential and proprietary information of Thales Group.
 *
 *  Thales Group MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 *  THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 *  TO THE IMPLIED WARRANTIES OR MERCHANTABILITY, FITNESS FOR A
 *  PARTICULAR PURPOSE, OR NON-INFRINGEMENT. Thales Group SHALL NOT BE
 *  LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS RESULT OF USING,
 *  MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.

 *  THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
 *  CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
 *  PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
 *  NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
 *  SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
 *  SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
 *  PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES"). Thales Group
 *  SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FTNESS FOR
 *  HIGH RISK ACTIVITIES;
 *
 */

package ciphertrustkms

//Api collections to generate a token, key pair, key list, sigin a message, and verify the message.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// This structure holds the verification status of a signature
type Verify struct {
	Verified bool
}

// This function sends a network call
// client: Represent the preparared HTTP Client
// req: Represent a prepared HTTP Request
// Return a HTTP Response in a format of a byte array, otherwise error
func sendMessage(client *http.Client, req *http.Request) ([]byte, error) {
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return body, nil
}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// payload: Represent the API data In
// contentType: Represent the Header Content Type
// Returns a Token structure. otherwise error
func NetworkHelperForCreateKey(method string, url string, payload *strings.Reader, contentType string) (*CipherTrustCryptoKey, error) {

	accessToken, err := TokenGenerator()
	if err != nil {
		fmt.Println("Cannot generate Token")
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken.Jwt)
	req.Header.Add("Content-Type", contentType)

	body, err := sendMessage(client, req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	key := CipherTrustCryptoKey{}

	err = json.Unmarshal(body, &key.Key)
	if err != nil {
		panic(err.Error())
	}

	return &key, nil

}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// Returns a Key structure otherwise error
func NetworkHelperForCreateKeyVersion(method string, url string) (*CipherTrustCryptoKey, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)

	body, err := sendMessage(client, req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	key := CipherTrustCryptoKey{}

	err = json.Unmarshal([]byte(body), &key.Key)
	if err != nil {
		log.Fatal(err)
	}

	return &key, nil

}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// payload: Represent the API data In
// contentType: Represent the Header Content Type
// Returns a Token structure. otherwise error
func NetworkHelperForToken(method string, url string, payload *strings.Reader, contentType string) (*AccessToken, error) {

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Content-Type", contentType)

	body, err := sendMessage(client, req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	Token := AccessToken{}

	err = json.Unmarshal([]byte(body), &Token)
	if err != nil {
		log.Fatal(err)
	}

	return &Token, nil

}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// accept: Represent response accept type
// Returns a Key structure otherwise error
func NetworkHelperForGetKey(method string, url string, accept string) (*CipherTrustCryptoKey, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("accept", accept)

	body, err := sendMessage(client, req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	key := CipherTrustCryptoKey{}

	err = json.Unmarshal([]byte(body), &key.Key)
	if err != nil {
		log.Fatal(err)
	}

	return &key, nil
}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// accept: Represent response accept type
// Returns an array of Key structure otherwise error
func NetworkHelperForListKeyVersions(method string, url string, accept string) (*CipherTrustCryptoKeysList, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("accept", accept)

	body, err := sendMessage(client, req)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	keys := CipherTrustCryptoKeysList{}

	err = json.Unmarshal(body, &keys)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return &keys, nil
}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
func NetworkHelperForDeleteKey(method string, url string) (bool, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)

	body, err := sendMessage(client, req)

	if err != nil {
		fmt.Println(err)
		return false, err
	}
	fmt.Println(body)
	return true, nil
}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// accept: Represent response accept type
// Returns an array of Key structure otherwise error
func NetworkHelperForListKeys(method string, url string, accept string) (*CipherTrustCryptoKeysList, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("accept", accept)

	body, err := sendMessage(client, req)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	keys := CipherTrustCryptoKeysList{}

	err = json.Unmarshal(body, &keys)
	if err != nil {
		fmt.Println(err)
	}
	return &keys, nil
}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// accept: Represent response accept type
// Returns an array of Key structure otherwise error
func NetworkHelperForListKeysByName(method string, url string, accept string) (*CipherTrustCryptoKeysList, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("accept", accept)

	body, err := sendMessage(client, req)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	ArrayKeysResponse := CipherTrustCryptoKeysList{}

	err = json.Unmarshal([]byte(body), &ArrayKeysResponse)
	if err != nil {
		log.Fatal(err)
	}

	return &ArrayKeysResponse, nil
}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// payload: Represent the API data In
// contentType: Represent the Header Content Type
// accept: Represent response accept type
// Returns a Signature structure otherwise error
func NetworkHelperForSign(method string, url string, payload *bytes.Reader, contentType string, accept string) (*SignResponse, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Accept", accept)

	body, err := sendMessage(client, req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	signatureResponse := SignResponse{}

	err = json.Unmarshal([]byte(body), &signatureResponse)
	if err != nil {
		log.Fatal(err)
	}

	return &signatureResponse, nil

}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// payload: Represent the API data In
// contentType: Represent the Header Content Type
// accept: Represent response accept type
// Returns a Verify structure otherwise error
func NetworkHelperForVerify(method string, url string, payload *strings.Reader, contentType string, accept string) (*Verify, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Accept", accept)

	body, err := sendMessage(client, req)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	verificationResponse := Verify{}

	err = json.Unmarshal([]byte(body), &verificationResponse)
	if err != nil {
		log.Fatal(err)
	}
	verify := Verify{}

	verify.Verified = verificationResponse.Verified

	return &verify, nil
}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// payload: Represent the API data In
// contentType: Represent the Header Content Type
// Returns a Verify structure otherwise error
func NetworkHelperForUpdateKeys(method string, url string, payload *strings.Reader, contentType string) (*Key, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("Content-Type", contentType)

	body, err := sendMessage(client, req)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	creatingKeyResponse := Key{}

	err = json.Unmarshal(body, &creatingKeyResponse)
	if err != nil {
		log.Fatal(err)
	}

	create := Key{}

	create.Version = creatingKeyResponse.Version

	return &create, nil

}

// This function format the Network Client header and request
// method: Represent the HTTP Method
// url: Represent the API endpoint
// payload: Represent the API data In
// contentType: Represent the Header Content Type
// Returns a Verify structure otherwise error
func NetworkHelperForUpdateKeyLabel(method string, url string, payload *strings.Reader, contentType string, accept string) (*Key, error) {
	token, err := TokenGenerator()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//certificate signed by unknown authority
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //not very secure
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	req.Header.Add("Authorization", token.TokenType+" "+token.Jwt)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Accept", accept)

	body, err := sendMessage(client, req)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	KeyResponse := Key{}

	err = json.Unmarshal(body, &KeyResponse)
	if err != nil {
		log.Fatal(err)
	}

	return &KeyResponse, nil

}
