$('#verify').on(verify);

function verify() { 
  const url = $("#verify").attr("file_pk");

  console.log(val)          
  console.log(url)
  $.post({                  
    url: "verify/"+url,                   
    data: {
        'success': true       
    },
    success: function (data) {   // `data` is the return of the `load_cities` view function
        $("#verified").html(data);  // replace the contents of the city input with the data that came from the server
        
    }
  });
}
$('#delete').on(deletes);

function deletes() { 
  const url = $("#delete").attr("file_pk");

 
  $.ajax({                  
    url: "verify/"+url,                   
    data: {
        'success': true       
    },
    success: function (data) {   // `data` is the return of the `load_cities` view function
        location.reload(); // replace the contents of the city input with the data that came from the server
        
    }
  });
}



