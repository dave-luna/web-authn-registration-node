if (!window.PublicKeyCredential) { alert("No, this won't work. Stop doing this."); }

console.log("hopefully works");

var publicKey = {
    challenge: new Uint8Array(%1$s).buffer,

    // Relying Party:
    rp: {
        name: "ForgeRock AS",
        id: "%2$s"
    },

    // User:
    user: {
        id: Uint8Array.from(window.atob("MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII="), c=>c.charCodeAt(0)),
        name: "demo@example.com",
        displayName: "Demo User",
        icon: "https://pics.example.com/00/p/aBjjjpqPb.png"
    },

    pubKeyCredParams: [
        {
            type: "public-key",
            alg: -7 // "ES256" as registered in the IANA COSE Algorithms registry
        },
        {
            type: "public-key",
            alg: -257 // Value registered by this specification for "RS256"
        }
    ],
        attestation: "%3$s",

// This Relying Party will accept either an ES256 or RS256 credential, but prefers an ES256 credential.
//     attestation: "direct",
    timeout: 60000, // 1 minute
    excludeCredentials: [], // No exclude list of PKCredDescriptors
    extensions: {"loc": true}  // Include location information in attestation
};

// Note: The following call will cause the authenticator to display UI.
navigator.credentials.create({ publicKey })
    .then(function (newCredentialInfo) {
        console.log(newCredentialInfo);
        console.log(newCredentialInfo.response.clientDataJSON);
        console.log(String.fromCharCode.apply(null, new Uint8Array(newCredentialInfo.response.clientDataJSON)));
        console.log(JSON.stringify(newCredentialInfo.response));
        console.log(newCredentialInfo.getClientExtensionResults());

        var rawId = newCredentialInfo.id;
        var clientData = String.fromCharCode.apply(null, new Uint8Array(newCredentialInfo.response.clientDataJSON));
        var keyData = new Int8Array(newCredentialInfo.response.attestationObject).toString();

        document.getElementById('webAuthNOutcome').value = clientData + "SPLITTER" + keyData + "SPLITTER" + rawId;
        document.getElementById("loginButton_0").click();
    }).catch(function (err) {
        console.error(err); // No acceptable authenticator or user refused consent. Handle appropriately.
});