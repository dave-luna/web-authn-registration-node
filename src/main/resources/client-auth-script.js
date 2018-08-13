if (!window.PublicKeyCredential) { alert("No, this won't work. Stop doing this."); }

console.log("trying to authenticate");

// var encoder = new TextEncoder();

var acceptableCredentials = [
    %2$s
];


console.log("id is");
console.log(acceptableCredentials[0].id);

var options = {
    challenge: new Uint8Array(%1$s).buffer,
    timeout: 60000,  // 1 minute
    allowCredentials: acceptableCredentials
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
        var clientData = String.fromCharCode.apply(null, new Uint8Array(assertion.response.clientDataJSON));
        var authenticatorData = new Int8Array(assertion.response.authenticatorData).toString();
        var signature = new Int8Array(assertion.response.signature).toString();
        var rawId = assertion.id;
        //
        document.getElementById('webAuthNOutcome').value = clientData + "SPLITTER" + authenticatorData + "SPLITTER" + signature + "SPLITTER" + rawId;
        document.getElementById("loginButton_0").click();
    }).catch(function (err) {
        console.error(err); // No acceptable authenticator or user refused consent. Handle appropriately.
});