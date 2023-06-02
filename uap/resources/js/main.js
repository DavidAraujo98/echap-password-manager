function login() {
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;

    if (password == "" || username == "") {
        swal("Por favor preencha todos os campos", "", "error");
    } else {
        var hash = sha3_512(password);
        var user = { "username": encode64(username), "hash": encode64(hash) };

        var queryString = window.location.search;
        var params = new URLSearchParams(queryString);

        if (params.get("service") == null) {
            $.ajax({
                type: "POST",
                url: "login_validation",
                data: JSON.stringify(user),
                contentType: "application/json",
                dataType: "json",
                success: function (data) {
                    response = jQuery.parseJSON(data);
                    if (response.success) {
                        dest = "vault?username=" + username;
                        swal(response.message, "", "success").then((e) => window.location.replace(dest));
                    } else {
                        swal(response.message, "", "error");
                    }
                }
            });
        } else {
            $.ajax({
                type: "POST",
                url: "service_validation",
                data: JSON.stringify(user),
                contentType: "application/json",
                dataType: "json",
                success: function (data) {
                    response = jQuery.parseJSON(data);
                    var dest = document.referrer + "login"
                    if (response.success) {
                        if (response.key != null) {
                            dest = dest + "?uap=" + response.key;
                            swal(response.message, "", "success").then((e) => window.location.replace(dest));
                        } else if (response.mux == 0) {
                            swal(response.message, "", "error");
                        } else if (response.mux == 1) {
                            option_modal(response.usernames);
                        } else {
                            swal(response.message, "", "error");
                        }
                    } else {
                        swal(response.message, "", "error");
                    }
                }
            });
        }
    }
}

function option_modal(list) {
    var ul = document.getElementById("options");

    list.forEach(element => {
        button = document.createElement("button");
        button.className = "list-group-item btn btn-primary";
        button.id = element;
        button.innerHTML = element;
        button.onclick = function () { selected(element); };
        ul.appendChild(button);
    });

    $("#optionsModal").modal("toggle");
}

function selected(id) {
    var optionsModal = document.getElementById('optionsModal');
    var modal = bootstrap.Modal.getInstance(optionsModal);
    modal.toggle();
    user = { "username": encode64(id) };
    $.ajax({
        type: "POST",
        url: "service_validation_afch",
        data: JSON.stringify(user),
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            var dest = document.referrer + "login"
            if (response.key != null) {
                dest = dest + "?uap=" + response.key;
                swal(response.message, "", "success").then((e) => window.location.replace(dest));
            } else {
                swal(response.message, "", "error").then((e) => window.location.replace(dest));;
            }
        }
    });
}

function signup() {
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    
    if (password == "" || username == "") {
        swal("Por favor preencha todos os campos corretamente", "", "error");
    } else {
        var hash = sha3_512(password);
        var newuser = { "username": encode64(username), "hash": encode64(hash)};

        $.ajax({
            type: "POST",
            url: "signup_validation",
            data: JSON.stringify(newuser),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                response = jQuery.parseJSON(data);
                if (response.success) {
                    dest = "vault?username=" + username;
                    swal(response.message, "", "success").then((e) => window.location.replace(dest));
                } else {
                    swal(response.message, "", "error");
                }
            }
        });
    }
}

function encode64(word) {
    word = sanitize(word)
    const a = CryptoJS.enc.Utf8.parse(word);
    const b = CryptoJS.enc.Base64.stringify(a);
    return b;
}

function decode64(word) {
    const a = CryptoJS.enc.Base64.parse(word);
    const b = CryptoJS.enc.Utf8.stringify(a);
    return b;
}

function sanitize(comment) {
    return String(comment).replace(/[^\w. ]/gi, function (c) {
        return '&#' + c.charCodeAt(0) + ';';
    });
}