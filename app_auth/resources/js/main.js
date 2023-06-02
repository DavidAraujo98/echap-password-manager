function uap_key_check() {
    var queryString = window.location.search;
    var urlParams = new URLSearchParams(queryString);
    key = urlParams.get("uap");

    if (key != null) {
        $.ajax({
            type: "POST",
            url: "uap_logger",
            dataType: "json",
            success: function (data) {
                response = jQuery.parseJSON(data);
                if (response.success) {
                    if (response.stocklink)
                        sessionStorage.setItem('stocklink', response.stocklink);
                    sessionStorage.setItem('session', 1);
                    sessionStorage.setItem('admin', response.admin);
                    sessionStorage.setItem('credit', response.credit);
                    swal(response.message, "", "success").then((e) => window.location.replace("index"));
                } else {
                    swal(response.message, "", "error");
                }
            }
        })
    }
}

function login() {
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;

    if (password == "" || username == "") {
        swal("Por favor preencha todos os campos", "", "error");
    } else {
        hash = sha3_512(password).hex();
        user = { "username": encode64(username), "hash": encode64(hash) }
        $.ajax({
            type: "POST",
            url: "login_validation",
            data: JSON.stringify(user),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                response = jQuery.parseJSON(data);
                sessionStorage.setItem('session', 1);
                sessionStorage.setItem('admin', response.admin);
                sessionStorage.setItem('credit', response.credit);
                if (response.stocklink)
                    sessionStorage.setItem('stocklink', response.stocklink);
                if (response.success) {
                    swal(response.message, "", "success").then((e) => window.location.replace("index"));
                } else {
                    swal(response.message, "", "error");
                }
            }
        })
    }
}

function uap() {
    $.ajax({
        type: "POST",
        url: "uap_validation",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            var host = window.location.host;
            var dest = "https://localhost:8080/?service=" + host + "&addr=" + response.address + "&prt=" + response.port;
            window.location.replace(dest);
        }
    });
}

function logout() {
    sessionStorage.clear();
    location.reload();
}

function signup() {
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    var email = document.getElementById("email").value;
    var credit = parseFloat(document.getElementById("credit").value).toFixed(2);
    
    if (password === "" || username === "" || email === "" || credit < 0 ) {
        swal("Por favor preencha todos os campos corretamente", "", "error");
    } else {
        var hash = sha3_512(password);
        var newuser = { "username": encode64(username), "email": encode64(email), "hash": encode64(hash), "credit": encode64(credit) };

        $.ajax({
            type: "POST",
            url: "signup_validation",
            data: JSON.stringify(newuser),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                response = jQuery.parseJSON(data);
                if (response.success) {
                    document.getElementById("form_signup").reset();
                    swal(response.message, "", "success").then((e) => window.location.replace("login"));
                } else {
                    swal(response.message, "", "error");
                }
            }
        });
    }
}

function reset() {
    var username = document.getElementById("username").value;

    if (username == "") {
        swal("Por favor preencha todos os campos", "", "error");
    } else {
        var user = { "username": encode64(username) }
        $.ajax({
            type: "POST",
            url: "reset_validation",
            data: JSON.stringify(user),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                response = jQuery.parseJSON(data);
                if (response.success) {
                    swal(response.message, "", "success");
                    document.getElementById("form_reset").reset();
                } else {
                    swal(response.message, "", "error");
                }
            }
        })
    }
}

function newpassword() {
    var password = document.getElementById("password").value;

    var queryString = window.location.search;
    var urlParams = new URLSearchParams(queryString);
    id = urlParams.get("id");

    hash = sha3_512(password).hex();

    data = { "resetid": encode64(id), "hash": encode64(hash) };
    $.ajax({
        type: "POST",
        url: "newpassword_validation",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            swal(response.message, "", "success");
            document.getElementById("form_newpassword").reset();
        }
    })
}

function prod_list() {
    $.ajax({
        type: "POST",
        url: "prod_list",
        contentType: "application/json",
        dataType: "json",
        beforeSend: function () {
            var load = document.getElementById("loader");
            load.style.display = "block";
        },
        success: function (data) {
            response = jQuery.parseJSON(data);
            row = document.getElementById("prod_list");
            for (var i = 0; i < response.length; i++) {
                var obj = response[i];

                var div = document.createElement("div");
                div.className = "col";

                var div1 = document.createElement("div");
                div1.className = "card shadow-sm";

                var img = document.createElement("img");
                img.className = "bd-placeholder-img card-img-top";
                img.width = "100%";
                img.height = "225";
                img.src = obj[3];

                var div2 = document.createElement("div");
                div.className = "card-body";

                var h5 = document.createElement("h5");
                h5.innerHTML = sanitize(obj[1]);

                var p = document.createElement("p");
                p.className = "card-text";

                p.innerHTML = sanitize(obj[2]);

                var div3 = document.createElement("div");
                div3.className = "d-flex justify-content-between align-items-center";

                var div4 = document.createElement("div");
                div4.className = "btn-group";

                var btn = document.createElement("a");
                btn.href = "products?id=" + obj[0];
                btn.className = "btn btn-sm btn-outline-secondary"

                var txt = document.createElement("text");
                txt.innerHTML = "View";

                btn.appendChild(txt);
                div4.appendChild(btn);
                div3.appendChild(div4);
                div2.appendChild(h5);
                div2.appendChild(p);
                div2.appendChild(div3);
                div1.appendChild(img);
                div1.appendChild(div2);
                div.appendChild(div1);

                row.appendChild(div);
            }
        },
    }).done(function () {
        var load = document.getElementById("loader");
        load.style.display = "None";
    });
}

function prod_load() {
    var queryString = window.location.search;
    var urlParams = new URLSearchParams(queryString);
    id = urlParams.get("id");
    id = sanitize(id);

    data = { "id": encode64(id), };
    $.ajax({
        type: "POST",
        url: "product_display",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            document.getElementById("price").innerHTML = response[4] + " €";
            document.getElementById("price").value = response[4];
            document.getElementById("main-image").src = response[3];
            document.getElementById("prod-name").innerHTML = sanitize(response[1]);
            document.getElementById("about").innerHTML = sanitize(response[2]);
            if (response[5] == 0) {
                document.getElementById("stock").innerHTML = "Sem stock";
                document.getElementById("button").disabled = true;
                document.getElementById("quantity").disabled = true;
            } else{
                document.getElementById("stock").innerHTML = "Em stock";
                if (document.getElementById("credits").value  >= response[4]) {
                    document.getElementById("button").disabled = false;
                } else {
                    document.getElementById("button").disabled = true;
                }
                document.getElementById("quantity").disabled = false;
                document.getElementById("quantity").max = response[5];
            }

        }
    }).done(get_reviews(id));
}

function buy() {
    var queryString = window.location.search;
    var urlParams = new URLSearchParams(queryString);
    item_id = urlParams.get("id");

    var quantity = Math.abs(parseInt($("#quantity").val()));
    var qmax = document.getElementById("quantity").max;
    var price = $("#price").val();
    var credits = $("#credits").val();
    
    if (value > credits) {
        swal("Credito insuficiente", "", "error");
    } else if(quantity < 0 || quantity > qmax){
         swal("Quantidade inválida", "", "error");
    }else {
        var value = (quantity * price);
        data = {"value": encode64(value), "product_id": encode64(item_id), "quantity": encode64(quantity) };
        $.ajax({
            type: "POST",
            url: "buy",
            data: JSON.stringify(data),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                response = jQuery.parseJSON(data);
                if (response.success) {
                    swal(response.message, "", "success");
                    var nv = credits - value;
                    sessionStorage.setItem("credit", nv.toFixed(2));
                } else {
                    swal(response.message, "", "error");
                }
            }
        });
    }
}

function get_reviews(id) {
    data = { "id": encode64(id), };
    $.ajax({
        type: "POST",
        url: "product_reviews",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            var list = document.getElementById("comments");
            for (var i = 0; i < response.length; i++) {
                var li = document.createElement("li");
                li.className = "list-group-item";

                var h6 = document.createElement("h6");
                h6.innerHTML = sanitize(response[i][2]);

                var p = document.createElement("p");
                p.innerHTML = sanitize(response[i][3]);

                li.appendChild(h6);
                li.appendChild(p);
                list.appendChild(li);
            }
        }
    });
}

function post_review() {
    var queryString = window.location.search;
    var urlParams = new URLSearchParams(queryString);
    id = urlParams.get("id");
    id = sanitize(id);

    var list = document.getElementById("comments");
    list.textContent = '';

    var comment = document.getElementById("comment");
    
    data = { "product_id": encode64(id), "comment": encode64(comment.value), };
    comment.textContent = '';

    $.ajax({
        type: "POST",
        url: "post_review",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
    }).done(get_reviews(id));
}

function show_hide() {
    admin = sessionStorage.getItem('admin');
    session = sessionStorage.getItem('session');
    credit = sessionStorage.getItem('credit');

    var loggedlist = document.getElementsByClassName("logged");
    var adminlist = document.getElementsByClassName("admin");
    var login_btn = document.getElementById("login_btn")
    if (session == 1) {
        document.getElementById("signup_btn").style.visibility = "hidden";
        document.getElementById("signup_btn").style.display = "none";
        document.getElementById("credits").innerHTML = credit;
        document.getElementById("credits").value = sanitize(credit);
        login_btn.innerHTML = "Logout";
        login_btn.setAttribute("onclick", "logout();")
        login_btn.removeAttribute("href");
        for (var i = 0; i < loggedlist.length; i++) {
            loggedlist[i].classList.add("visible");
        }
        if (admin != 0) {
            for (var i = 0; i < adminlist.length; i++) {
                adminlist[i].classList.add("visible");
            }
            var nav = document.getElementById("nav");
            var li = document.createElement("li");
            li.setAttribute("id", "stock_btn");

            var a = document.createElement("a");
            a.setAttribute("href", sessionStorage.getItem('stocklink'));
            a.className = "nav-link px-2 text-warning";
            a.innerHTML = "Stock Management"

            li.appendChild(a);
            nav.appendChild(li);
        }
    } else {
        document.getElementById("signup_btn").style.visibility = "visible";
        document.getElementById("signup_btn").style.display = "inline";
        login_btn.innerHTML = "Login";
        login_btn.removeAttribute("onclick");
        login_btn.setAttribute("href", "login");
        document.getElementById("stock_btn").remove();
        for (var i = 0; i < loggedlist.length; i++) {
            loggedlist[i].classList.remove("visible");
        }
        for (var i = 0; i < adminlist.length; i++) {
            adminlist[i].classList.remove("visible");
        }
    }
}

function encode64(word) {
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
