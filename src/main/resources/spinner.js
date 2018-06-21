var newLocation = document.getElementById("content");
newLocation.getElementsByTagName("fieldset")[0].innerHTML += "<div class=\"panel panel-default\">\n" +
    "    <div class=\"panel-body text-center\">\n" +
    "    <h4 class=\"awaiting-response\">\n" +
    "    <i class=\"fa fa-circle-o-notch fa-spin text-primary\"></i> %1$s </h4>\n" +
    "    </div>\n" +
    "</div>";
document.body.appendChild(newLocation);


