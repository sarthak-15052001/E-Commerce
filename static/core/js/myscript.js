$('#slider1, #slider2, #slider3, #slider4, #slider5, #slider6').owlCarousel({
    loop: true,
    margin: 20,
    responsiveClass: true,
    responsive: {
        0: {
            items: 1,
            nav: false,
            autoplay: true,
        },
        600: {
            items: 3,
            nav: true,
            autoplay: true,
        },
        1000: {
            items: 5,
            nav: true,
            loop: true,
            autoplay: true,
        }
    }
})

$('.plus-cart').click(function(){
  var id = $(this).attr("pid").toString();
  var eml = $(this).closest('.input-group').find('.form-control'); // Find the input element within the same input-group
//   console.log(id)
  $.ajax({
    type:"GET",
    url:"/pluscart",
    data:{
        prod_id: id
    },
    success: function(data){
        console.log(data)
        eml.val(data.quantity); // Set the value of the input element
        document.getElementById("amount").innerText = data.amount
        document.getElementById("totalamount").innerText = data.total_amount
        // document.getElementById("tempamount").innerText = data.temp_amount
        $("#" + data.cart_id).text(data.product_price);
    }
  });
});


$('.minus-cart').click(function(){
    var id = $(this).attr("pid").toString();
    var eml = $(this).closest('.input-group').find('.form-control'); // Find the input element within the same input-group
    // console.log(id)
    $.ajax({
      type:"GET",
      url:"/minuscart",
      data:{
          prod_id: id
      },
      success: function(data){
          console.log(data)
          eml.val(data.quantity); // Set the value of the input element
          document.getElementById("amount").innerText = data.amount
          document.getElementById("totalamount").innerText = data.total_amount
        //   document.getElementById("tempamount").innerText = data.temp_amount
          $("#" + data.cart_id).text(data.product_price);
      }
    });
  });



  $('.remove-cart').click(function(){
    var id = $(this).attr("pid").toString();
    console.log(id)
    $.ajax({
      type:"GET",
      url:"/removecart",
      data:{
          prod_id: id
      },
      success: function(data){
          console.log("delete")
          document.getElementById("amount").innerText = data.amount
          document.getElementById("totalamount").innerText = data.total_amount
          document.getElementById("tempamount").innerText = data.temp_amount
          $(this).closest('tr').remove();
      }
    });
  });