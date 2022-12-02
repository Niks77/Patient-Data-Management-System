$('#type').change(changeFileUpload);

function changeFileUpload() { 
  const url = $("#submitForm").attr("data-dropdown-url");
  const val = $(this).val()
  $.ajax({                  
    url: url,                   
    data: {
        'type': val       
    },
    success: function (data) {   // `data` is the return of the `load_cities` view function
        $("#fileUpload").html(data);  // replace the contents of the city input with the data that came from the server
        
    }
  });
}
$('#type').find('option[selected="selected"]').each(function(){
  $(this).prop('selected', true);
});

