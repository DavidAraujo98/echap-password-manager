function open() {
    var queryString = window.location.search;
    var urlParams = new URLSearchParams(queryString);
    document.getElementById("username").innerHTML = sanitize(urlParams.get("username"));
    
    $.ajax({
        type: "POST",
        url: "loadData",
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            var creds = response.creds;
            for (var i = 0; i < creds.length; i++){
                newEntry(decode64(creds[i].id), decode64(creds[i].service), decode64(creds[i].username));
            }
        }
    })
}

function logout() {
    swal({
        title: "Are you sure?",
        text: "Once logout, all changes will be saved and database encrypted",
        icon: "warning",
        buttons: true,
        dangerMode: true,
        })
        .then((willDelete) => {
            if (willDelete) {
                swal("Changes saved and database encrypted","", "success").then((e) => window.location.replace("logout"));
            }
    });
}

function visible() {
    var x = document.getElementById("fpassword");
    if (x.type === "password") {
        x.type = "text";
    } else {
        x.type = "password";
    }
}

function newCredentials() {
    var list = document.getElementById("list");

    var user = $("#fusername").val();
    var pass = $("#fpassword").val();
    var serv = $("#fservice").val();

    if (!(user != "" && pass != "" && serv != "")) {
        swal("All field are required to log the credentials", "", "error");
    } else {
        var id = list.childElementCount + user;
        if (window.sessionStorage.getItem("id") != null) {
            id = window.sessionStorage.getItem("id");
            window.sessionStorage.removeItem("id");
        }
        
        var data = { "id": encode64(id), "service": encode64(serv), "username": encode64(user), "password": encode64(pass) };
        
        $.ajax({
            type: "POST",
            url: "newCredentials",
            data: JSON.stringify(data),
            contentType: "application/json",
            dataType: "json",
            success: function (data) {
                response = jQuery.parseJSON(data);
                if (response.success) {
                    if (response.new) {
                        newEntry(id, serv, user)
                    }
                    swal(response.message, "", "success").then(() => { $("#modalCreator").modal('hide'); window.location.reload() });
                } else {
                    swal(response.message, "", "error").then($("#modalCreator").modal('hide'));
                }
            }
        });
    }
    
}

function newEntry(id, service, username) {
    var list = document.getElementById("list");
    var div = document.createElement("div");
    div.id = id;
    div.className = "row justify-content-md-center py-2 border-bottom";

    var input = document.createElement("input");
    input.type = "checkbox";
    input.className = "col-sm-1 form-check-input";

    var div1 = document.createElement("div");
    div1.className = "col-11";
    div1.onclick = function () { details(id); };
    div1.setAttribute("data-bs-toggle", "modal");
    div1.setAttribute("data-bs-target", "#modalCreator");

    var ul = document.createElement("ul");
    ul.className = "row justify-content-end";

    var h6_1 = document.createElement("h6")
    h6_1.innerHTML = service;
    h6_1.className = "col-6 text-end";

    var h6_2 = document.createElement("h6")
    h6_2.innerHTML = username;
    h6_2.className = "col-6 text-end";
    
    ul.appendChild(h6_1);
    ul.appendChild(h6_2);
    div1.appendChild(ul);
    div.appendChild(input);
    div.appendChild(div1);
    list.appendChild(div);

    parent = list.parentElement;
    parent.hidden = false;
}

function deleteSelection() {
    var list = document.getElementById("list");
    var children = list.children;
    data = { "ids": [] };
    for (let i = 0; i < children.length; i++) {
        var div = children[i];
        var ck = div.getElementsByTagName("input")[0];
        if (ck.checked) {
            data["ids"].push(encode64(div.id));
            list.removeChild(div);
            i--;
        }
    }
    if (children.length == 0) {
        parent = list.parentElement;
        parent.hidden = true;
    }
    $.ajax({
        type: "POST",
        url: "deleteSelection",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            swal(response.message, "", "success");
        }
    });
}

function selectAll() {
    var list = document.getElementById("list");
    var children = list.children;
    var b = document.getElementById("selectall");
    if (b.value === "false") {
        b.value = "true";
        for (let i = 0; i < children.length; i++) {
            var ul = children[i];
            var ck = ul.getElementsByTagName("input")[0];
            ck.checked = true;
        }
    } else {
        b.value = "false";
        for (let i = 0; i < children.length; i++) {
            var ul = children[i];
            var ck = ul.getElementsByTagName("input")[0];
            ck.checked = false;
        }
    }
}

function details(id) {
    window.sessionStorage.setItem("id", id);
    ul = document.getElementById(id);
    document.getElementById("fservice").value = ul.getElementsByTagName("h6")[0].innerHTML;
    document.getElementById("fusername").value = ul.getElementsByTagName("h6")[1].innerHTML;
    data = { "id": encode64(id) };
    $.ajax({
        type: "POST",
        url: "getPassword",
        data: JSON.stringify(data),
        contentType: "application/json",
        dataType: "json",
        success: function (data) {
            response = jQuery.parseJSON(data);
            document.getElementById("fpassword").value = decode64(response.password);
        }
    });
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

$(document).ready(function() {
  $(".modal").on("hidden.bs.modal", function() {
    $(".modal-body input").val("");
  });
});