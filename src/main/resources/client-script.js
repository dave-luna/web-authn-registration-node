
(function(output) {
    var autoSubmitDelay = 0,
        submitted = false;
    function submit() {
        if (submitted) {
            return;
        }
        document.getElementById("loginButton_0").click();
        submitted = true;
    }
    // script
    output.value = "true";
    console.log(output);

    setTimeout(submit, autoSubmitDelay);
})(document.forms[0].elements['testoutcome']);
