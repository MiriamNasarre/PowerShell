﻿$cad="http://www.youtube.com/watch_videos?video_ids="
#Para crear la lista de reproduccion en youtube añadir el id de la url en el array id
$id=@("_z4c4ftKZ1Y","PzlVjgKzyBY","tb5oO3b8sDw",
"ImJlQKBbsnc","4c-FIRz8vFY","Lw2knN6nMTg","KXKYzYzOFac",
"C5w-bgMnQt0","Pk2XqJJSByg","bg0v7gHooZk","DzpKOM8OgtA","ITvtvcBOtRE","hLL8QfgOoXs","TAFlK5HdfM8","rVu04qpsu00","wsYP1VjOSX8","66KhckYmRp4","dd-FKxrpBEw","FoawtTeleCA","y7chwkrQBh4","VCgICvIQeV0","myxYCYjZQYs","kf1YTIEkWgE","iIp6UPAk3lQ","d_s1jBgB_bM","EIig3ng5FEE","lZgSdPlRupw","BRcrbDGFiUY","IfZ0dbmKRZM","MMrKVExmLb4","zLgJsKbzzpY","8j9hG-nVkLc","FSXuM2v0YLY","HF3DCgjpjvs")

for($i=0;$i -lt $id.length;$i++){
    if($i -eq $id.length-1){
       $cad+=$id[$i].toString().trim()
        start firefox $cad.trim()
    }else{
	    $cad+=$id[$i].toString().trim()+","
	}
}


