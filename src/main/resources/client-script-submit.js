
(function(output) {
    var autoSubmitDelay = 30000,
        submitted = false;
    function submit() {
        if (submitted) {
            return;
        }
        document.getElementById("loginButton_0").click();
        submitted = true;
    }

    %1$s

    setTimeout(submit, autoSubmitDelay);
})(document.forms[0].elements['outcome']);
