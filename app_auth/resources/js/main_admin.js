function prod_list_admin() {
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

                var li = document.createElement("li");
                li.className = "list-group-item d-flex justify-content-between align-items-center row row-cols-5";
                li.setAttribute("id", obj[0]);

                var input = document.createElement("input");
                input.className = "form-check-input me-1 col";
                input.type = "checkbox";

                var label = document.createElement("label");
                label.className = "col";
                label.innerHTML = "ID: " + sanitize(obj[0]);

                var label1 = document.createElement("label");
                label1.className = "col";
                label1.innerHTML = sanitize(obj[1]);

                var input1 = document.createElement("label");
                input1.className = "col";
                input1.placeholder = "Preco";
                input1.innerHTML = sanitize(obj[4])+ " €";

                var span = document.createElement("span");
                span.className = "badge bg-primary rounded-pill col";
                span.innerHTML = sanitize(obj[5]);

                li.appendChild(input);
                li.appendChild(label);
                li.appendChild(label1);
                li.appendChild(input1);
                li.appendChild(span);
                row.appendChild(li);
            }
        },
    }).done(function () {
        var load = document.getElementById("loader");
        load.style.display = "None";
    });
}

function add_details() {
    var name = document.getElementById("name").value;
    var detail = document.getElementById("detail").value;
    var price = document.getElementById("price").value;
    var quantity = document.getElementById("quantity").value;
    var image = document.getElementById('image').files[0];

    if (name == "" || detail == "" || price == "" || quantity == "" || image == "") {
        alert('Preencha os campos necessários');
    } else {
        var newprod = { "name": encode64(name), "detail": encode64(detail), "price": encode64(price), "quantity": encode64(quantity) };

        $.ajax({
            type: "POST",
            url: "prod_add",
            data: JSON.stringify(newprod),
            contentType: "application/json",
            dataType: "json",
        })
        
    }   
}
    
function remove() {
    erase = false;
    var ul = document.getElementById("prod_list");
    var items = ul.getElementsByTagName("li");
    var data = [];
    for (var i = 0; i < items.length; i++) {
        if (items[i].getElementsByClassName("form-check-input")[0].checked) {
            data.push({ "id": encode64(items[i].id) });
        }
    }
    if (data.length == 0) {
        swal('Não há produtos selecionados', '', 'error')
    } else {
        for (var i = 0; i < data.length; i++) {
            document.getElementById(decode64(data[i].id)).remove();
        }
        $.ajax({
            type: "POST",
            url: "prod_remove",
            data: JSON.stringify(data),
            contentType: "application/json",
            dataType: "json",
        }).done(
            swal('Produtos apagados', '', 'warning')
        )
    }
}
