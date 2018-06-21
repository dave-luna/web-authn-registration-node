if (!window.PublicKeyCredential) { alert("No, this won't work. Stop doing this."); }

var publicKey = {
    challenge: new Uint8Array(%1$s),

    // Relying Party:
    rp: {
        name: "ForgeRock AS"
    },

    // User:
    user: {
        id: Uint8Array.from(window.atob("MIIBkzCCATigAwIBAjCCAZMwggE4oAMCAQIwggGTMII="), c=>c.charCodeAt(0)),
    name: "demo@example.com",
    displayName: "Demo User",
    icon: "https://pics.example.com/00/p/aBjjjpqPb.png"
},

// This Relying Party will accept either an ES256 or RS256 credential, but prefers an ES256 credential.
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

    timeout: 60000, // 1 minute
    excludeCredentials: [], // No exclude list of PKCredDescriptors
    extensions: {"loc": true}  // Include location information in attestation
};

// Note: The following call will cause the authenticator to display UI.
navigator.credentials.create({ publicKey })
    .then(function (newCredentialInfo) {
        alert(newCredentialInfo); // Send new credential info to server for verification and registration.
    }).catch(function (err) {
        alert(err); // No acceptable authenticator or user refused consent. Handle appropriately.
});