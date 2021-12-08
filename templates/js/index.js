$(document).ready(function(){
    $("#formFrontEnd").validetta({
        bubblePosition: "bottom",
        bubbleGapTop: 10,
        bubbleGapLeft: -5,
        onValid:function(e){
            e.preventDefault();
            var boleta = $("#boleta").val();
            var contrasena = $("#contrasena").val();
            $.alert({
                title:"<h4>TWeb - Sem. 20202</h4>",
                content:"<h5>Boleta: "+boleta+"<br>Contrasena: "+contrasena+"</h5>",
                icon:"fas fa-cogs fa-2x",
                type:"green",
                theme:"supervan"
            });
        }
    });
});