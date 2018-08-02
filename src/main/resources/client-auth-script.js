if (!window.PublicKeyCredential) { alert("No, this won't work. Stop doing this."); }

console.log("trying to authenticate");

// var encoder = new TextEncoder();

var acceptableCredential = {
    type: "public-key",
    id: new Int8Array(%2$s).buffer
};

console.log("id is");
console.log(acceptableCredential.id);

var options = {
    challenge: new Uint8Array(%1$s).buffer,
    timeout: 60000,  // 1 minute
    allowCredentials: [acceptableCredential]
};

// Note: The following call will cause the authenticator to display UI.
navigator.credentials.get({ "publicKey" : options })
    .then(function (assertion) {
        console.log(assertion);
        // console.log(newCredentialInfo.response.clientDataJSON);
        // console.log(String.fromCharCode.apply(null, new Uint8Array(newCredentialInfo.response.clientDataJSON)));
        // console.log(JSON.stringify(newCredentialInfo.response));
        // console.log(newCredentialInfo.getClientExtensionResults());
        //
        // var clientData = String.fromCharCode.apply(null, new Uint8Array(newCredentialInfo.response.clientDataJSON));
        // var keyData = new Int8Array(newCredentialInfo.response.attestationObject).toString();
        //
        document.getElementById('webAuthNOutcome').value = "Hello";
        document.getElementById("loginButton_0").click();
    }).catch(function (err) {
        console.error(err); // No acceptable authenticator or user refused consent. Handle appropriately.
});