$r="Si"
$ruta=get-location

Function CrearDirectorio {

do{
$ruta=get-location
echo "$ruta"
$respuesta=read-host "Quieres cambiar de directorio"


if($respuesta -eq "No"){
	$nombre=Read-Host "Nombre del directorio a crear"
	if(-not (test-path $nombre)){
		ni $nombre -type directory
		echo "Se ha creado el directorio $nombre"
	}else{
		echo "El directorio $nombre ya existe."
	}
}elseif($respuesta -eq "Si"){
	$res=read-host "Quieres ir al directorio anterior u a otro"
	if($res -eq "otro"){
		$rut=read-host "Introduce la ruta:"
		cd $rut
	$nombre=Read-Host "Nombre del directorio:"
	if(-not (test-path $nombre)){
		ni $nombre -type directory
	echo "Se ha creado el directorio $nombre"
	}else{
		echo "El directorio $nombre ya existe."
	}
	}elseif ($res -eq "anterior"){
		cd..
		$nombre=Read-Host "Nombre del directorio"
	if(-not (test-path $nombre)){
		ni $nombre -type directory
	echo "Se ha creado el directorio $nombre"
	}else{
		echo "El directorio $nombre ya existe."
	}
	}else{
		echo "No has seleccionado ninguna opcion"
		break;
		get-menu
	}
		
		
}else{
	echo "No has contestado si o no asi que has vuelto al menu"
	break;
	get-menu
	
}
write-host ""
$r=read-host "Quieres crear otro directorio"
}while($r -eq "Si")
}

Function BorrarDirectorio{
do{
$ruta=get-location
echo "$ruta"
$respuesta=read-host "Quieres cambiar de directorio"


if($respuesta -eq "No"){
	$nombre=Read-Host "Nombre del directorio a borrar"
	if(-not (test-path $nombre)){
	echo "El directorio $nombre no existe."
		
	}else{
		rm $nombre 
		echo "Se ha eliminado el directorio $nombre"
	}
}elseif($respuesta -eq "Si"){
	$res=read-host "Quieres ir al directorio anterior u a otro"
	if($res -eq "otro"){
		$rut=read-host "Introduce la ruta:"
		cd $rut
	$nombre=Read-Host "Nombre del directorio:"
	if(-not (test-path $nombre)){
		echo "El directorio $nombre no existe."
	echo "Se ha creado el directorio $nombre"
	}else{
		rm $nombre 
		echo "Se ha eliminado el directorio $nombre"
	}
	}elseif ($res -eq "anterior"){
		cd..
		$nombre=Read-Host "Nombre del directorio"
	if(-not (test-path $nombre)){
		echo "El directorio $nombre no existe."
	}else{
		rm $nombre 
		echo "Se ha eliminado el directorio $nombre"
	}
	}else{
		echo "No has seleccionado ninguna opcion"
		break;
		get-menu
	}
		
		
}else{
	echo "No has contestado si o no asi que has vuelto al menu"
	break;
	get-menu
	
}
write-host ""
$r=read-host "Quieres borrar otro directorio"
}while($r -eq "Si")
}

Function CrearFichero {
do{
$ruta=get-location
echo "Estas en $ruta"
$respuesta=read-host "Quieres cambiar de directorio"

if($respuesta -eq "No"){
	$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		ni $nombre -type file
		echo "Se ha creado el fichero $nombre"
	}else{
		echo "El fichero $nombre ya existe."
	}
}elseif($respuesta -eq "Si"){
	$res=read-host "Quieres ir al directorio anterior u a otro"
	if($res -eq "otro"){
		$rut=read-host "Introduce la ruta:"
		cd $rut
	$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		ni $nombre -type file
		echo "Se ha creado el fichero $nombre"
	}else{
		echo "El fichero $nombre ya existe."
	}

	}elseif($res -eq "anterior"){
		cd..
		$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		ni $nombre -type file
	echo "Se ha creado el fichero $nombre"
	}else{
		echo "El fichero $nombre ya existe."
	}
	}else{
		echo "No has seleccionado ninguna opcion"
		break;
		get-menu
	}
		
		
}else{
	echo "No has contestado si o no asi que has vuelto al menu"
	break;
	get-menu
	
}
write-host ""
$r=read-host "Quieres crear otro fichero"
}while($r -eq "Si")
}


Function BorrarFichero{
do{
$ruta=get-location
echo "Estas en $ruta"
$respuesta=read-host "Quieres cambiar de directorio"

if($respuesta -eq "No"){
	$nombre=Read-Host "Nombre del fichero a borrar "
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe"
	}else{
		rm $nombre 
		echo "Se ha borrado el fichero $nombre"

	}
}elseif($respuesta -eq "Si"){
	$res=read-host "Quieres ir al directorio anterior u a otro"
	if($res -eq "otro"){
		$rut=read-host "Introduce la ruta:"
		cd $rut
	$nombre=Read-Host "Nombre del fichero a borrar"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe"
	}else{
		rm $nombre 
		echo "Se ha borrado el fichero $nombre"
	}	
	}elseif ($res -eq "anterior"){
		cd..
		$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre ya existe."
		
	}else{
		rm $nombre 
		echo "Se ha borrado el fichero $nombre"
	}
	}else{
		echo "No has contestado si o no asi que has vuelto al menu"
		break;
		get-menu
	
	}
		
		
}else{
	echo "No has contestado si o no asi que has vuelto al menu"
	break;
	get-menu
}

write-host ""
$r=read-host "Quieres borrar otro fichero"
}while($r -eq "Si")
}

Function VerFichero {
$ruta=get-location
echo "Estas en $ruta "
do{
$respuesta=read-host "Quieres cambiar de directorio"

if($respuesta -eq "No"){
	$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe."
	}else{
		cat $nombre 
	}
}elseif($respuesta -eq "Si"){
	$res=read-host "Quieres ir al directorio anterior u a otro"
	if($res -eq "otro"){
		$rut=read-host "Introduce la ruta:"
		cd $rut
	$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El directorio $nombre no existe."
	}else{
		cat $nombre
		}
	}elseif ($res -eq "anterior"){
		cd..
		$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe"
	}else{
		cat $nombre
	}
	}else{
		echo "No has contestado si o no asi que has vuelto al menu"
		break;
		get-menu
	
	}
}else{
	echo "No has contestado si o no asi que has vuelto al menu"
	break;
	get-menu
}
write-host ""
$r=read-host "Quieres ver otro fichero"
}while($r -eq "Si")
}

Function ListarDirectorios{
$ruta=get-location
echo "Estas en $ruta "
dir
pause
}

Function CambiarDirectorio{
	$nombre= read-host "A donde quieres ir?"
	if(-not (test-path $nombre)){
		echo "El directorio $nombre no existe."
	}else{
		cd $nombre
		$ruta=get-location
		echo "Estas en $ruta "
	}
	pause
}


Function CrearusuariosAd{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\NewUsers.csv
foreach($user in $csvcontent){
	New-ADUser -name $user.name -SamAccountName $user.SamAccountName -AccountPassword (ConvertTo-SecureString “P4ssw0rd” -AsPlainText -Force)-ChangePasswordAtLogon $true -DisplayName $user.DisplayName -givenname $user.Nombre -surname $user.Apellido  -Description $user.Descripcion -Office $user.Oficina -City $user.Ciudad -Country $user.Pais -Title $user.Title -Department $user.Departamento -Company $user.Empresa -Email $user.email-Enabled $true -path $user.UnidadOrganizativa
	echo "Se ha creado el usuario $user.SamAccountName"
}


}


Function BorrarusuariosAd{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\Eliminausuarios.csv
echo "Se van a eliminar los siguientes usuarios del directorio activo."
cat c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\Eliminausuarios.csv|fl

foreach($user in $csvcontent){
	Remove-ADUser $user.Usuario
}
}


Function ListarUsuariosAD{
	get-aduser -filter *

}

Function CrearGruposAd{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\NewGroups.csv
foreach($group in $csvcontent){
	New-ADGroup -Name $group.Nombre -SamAccountName $group.nombre -GroupCategory $group.Tipo -GroupScope $group.Ambito -DisplayName $group.nombre  -Description $group.descripcion -path $group.uo
	echo "Se ha creado el grupo "+$group.nombre
	}
}

Function UnirusuariosAGrupos{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\anadir_usuarios_a_grupos.csv
foreach ($user in $csvcontent){
	Add-AdGroupMember -Identity $user.grupo -Members $user.usuario
	echo "Se ha anadido al usuario $user"
}
}






Function BorrarFichero{
do{
$ruta=get-location
echo "Estas en $ruta"
$respuesta=read-host "Quieres cambiar de directorio"

if($respuesta -eq "No"){
	$nombre=Read-Host "Nombre del fichero a borrar "
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe"
	}else{
		rm $nombre 
		echo "Se ha borrado el fichero $nombre"

	}
}elseif($respuesta -eq "Si"){
	$res=read-host "Quieres ir al directorio anterior u a otro"
	if($res -eq "otro"){
		$rut=read-host "Introduce la ruta:"
		cd $rut
	$nombre=Read-Host "Nombre del fichero a borrar"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe"
	}else{
		rm $nombre 
		echo "Se ha borrado el fichero $nombre"
	}	
	}elseif ($res -eq "anterior"){
		cd..
		$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre ya existe."
		
	}else{
		rm $nombre 
		echo "Se ha borrado el fichero $nombre"
	}
	}else{
		echo "No has contestado si o no asi que has vuelto al menu"
		break;
		get-menu
	
	}
		
		
}else{
	echo "No has contestado si o no asi que has vuelto al menu"
	break;
	get-menu
}

write-host ""
$r=read-host "Quieres borrar otro fichero"
}while($r -eq "Si")
}

Function VerFichero {
$ruta=get-location
echo "Estas en $ruta "
do{
$respuesta=read-host "Quieres cambiar de directorio"

if($respuesta -eq "No"){
	$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe."
	}else{
		cat $nombre 
	}
}elseif($respuesta -eq "Si"){
	$res=read-host "Quieres ir al directorio anterior u a otro"
	if($res -eq "otro"){
		$rut=read-host "Introduce la ruta:"
		cd $rut
	$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El directorio $nombre no existe."
	}else{
		cat $nombre
		}
	}elseif ($res -eq "anterior"){
		cd..
		$nombre=Read-Host "Nombre del fichero"
	if(-not (test-path $nombre)){
		echo "El fichero $nombre no existe"
	}else{
		cat $nombre
	}
	}else{
		echo "No has contestado si o no asi que has vuelto al menu"
		break;
		get-menu
	
	}
}else{
	echo "No has contestado si o no asi que has vuelto al menu"
	break;
	get-menu
}
write-host ""
$r=read-host "Quieres ver otro fichero"
}while($r -eq "Si")
}

Function ListarDirectorios{
$ruta=get-location
echo "Estas en $ruta "
dir
pause
}

Function CambiarDirectorio{
	$nombre= read-host "A donde quieres ir?"
	if(-not (test-path $nombre)){
		echo "El directorio $nombre no existe."
	}else{
		cd $nombre
		$ruta=get-location
		echo "Estas en $ruta "
	}
	pause
}


Function CrearusuariosAd{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\NewUsers.csv
foreach($user in $csvcontent){
	New-ADUser -name $user.name -SamAccountName $user.SamAccountName -AccountPassword (ConvertTo-SecureString “P4ssw0rd” -AsPlainText -Force)-ChangePasswordAtLogon $true -DisplayName $user.DisplayName -givenname $user.Nombre -surname $user.Apellido  -Description $user.Descripcion -Office $user.Oficina -City $user.Ciudad -Country $user.Pais -Title $user.Title -Department $user.Departamento -Company $user.Empresa -Email $user.email-Enabled $true -path $user.UnidadOrganizativa
	echo "Se ha creado el usuario $user.SamAccountName"
}


}


Function BorrarusuariosAd{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\Eliminausuarios.csv
echo "Se van a eliminar los siguientes usuarios del directorio activo."
cat c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\Eliminausuarios.csv|fl
$respuesta=Read-host "Esta seguro"

if($respuesta -eq "Si"){
foreach($user in $csvcontent){
	Remove-ADUser $user.Usuario
	echo "Se ha eliminado el usuario $user.SamAccountName"
}
}else{
	echo "No se ha eliminado ningun usuario"

}
}


Function ListarUsuariosAD{
	get-aduser -filter *

}



Function Ayuda{
$ruta="c:\users\administrador\desktop\ayuda"
if(-not(test-path $ruta)){
md $ruta
}
cd $ruta
$modulos=@(get-command | select-object  moduleName -unique)
foreach($modulo in $modulos){
	$ficheros=@(($modulo).ModuleName.toString().replace(".","-")+".txt")
foreach($fichero in $ficheros){
	$comandos+=(get-command|select name|where modulename -eq $fichero.toString().split('.')[0])
	for($i=0;$i -lt $comandos.length;$i++){
		get-help $comandos[$i] > $fichero
	}
}
}
}

Function CrearUO{
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\Unidades_Organizativas.csv
foreach($uo in $csvcontent){
	New-ADOrganizationalUnit -Name $uo.nombre -Description $uo.Descripcion -path $uo.uo
	echo "Se ha creado la unidad organizativa $uo.nombre"
}
}


Function BorrarUO{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\Borrar_Unidades_Organizativas.csv
foreach($uo in $csvcontent){

Get-ADOrganizationalUnit -Identity $uo.unidadorganizativa |
    Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru |
    Remove-ADOrganizationalUnit -Confirm:$true
    echo "Se ha eliminado la unidad organizativa $uo.uo"
}

}

Function ListarUO{
	get-adorganizationalunit -filter *
}

Function EliminarusuariosDeGruposAD {
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\quitar_usuarios_de_grupos.csv
foreach ($user in $csvcontent)
{
Remove-AdGroupMember -Identity $user.grupo -Members $user.usuario
echo "Se ha eliminado al users $user.users del grupo $user.grupo"
}

}

Function ListarGruposAd{
	get-adgroup -filter *

}

Function UsuariosDeUnGrupo{
	$grupo=Read-Host "Introduce un grupo para saber que usuarios pertenecen a dicho grupo"
	get-adgroupmember -identity $grupo

}
Function BorrarGruposAd{
Import-Module ActiveDirectory
$users= Import-Csv -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\eliminagrupos.csv
foreach ($i in $users){
	Remove-ADGroup $i.nombre
	echo "Se ha eliminado el grupo $i.nombre"
}

}


Function ExportarGPOs {
	cd c:\users\Administrador\desktop
	md directivas_grupo
	cd directivas_grupo
	Get-GPO -All | % {$_.GenerateReport('xml') | Out-File "$($_.DisplayName).xml"}
}

Function CambiarPasswordaUsuario {
$Password = Read-Host "Introduce la nueva password" -AsSecureStrin
$usuario=Read-Host "Introduzca el usuario al que se le va a cambiar el password cn=xxx,ou=xxx,ou=xxx,dc=xxx,dc=xxx sin comillas"
Set-AdAccountPassword  $usuario -reset -newpassword $password
}

Function CambiarPasswordaVariosuarios {
Import-Module ActiveDirectory
	$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\cambiar_password.csv
	foreach ($uo in $csvcontent){
	
	$Pass = Read-Host "Introduce la nueva password para $uo" -AsSecureStrin
	Set-AdAccountPassword $uo.UnidadOrganizativa -reset -newpassword $pass
	}

}


Function Salir{
	exit
	
}



Function EliminarusuariosDeGruposAD {
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\quitar_usuarios_de_grupos.csv
foreach ($user in $csvcontent)
{
Remove-AdGroupMember -Identity $user.grupo -Members $user.usuario
echo "Se ha eliminado al users $user.users del grupo $user.grupo"
}

}

Function ListarGruposAd{
	get-adgroup -filter *

}

Function UsuariosDeUnGrupo{
	$grupo=Read-Host "Introduce un grupo para saber que usuarios pertenecen a dicho grupo"
	get-adgroupmember -identity $grupo

}
Function BorrarGruposAd{
Import-Module ActiveDirectory
$users= Import-Csv -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\eliminagrupos.csv
foreach ($i in $users){
	Remove-ADGroup $i.nombre
	echo "Se ha eliminado el grupo $i.nombre"
}

}




Function TestConnection{
	echo "Introduce un dominio(www.google.es) o una direccion ip (192.168.10.4) puedes comprobar varios cuando no quieras introducir mas datos dejar el array en blanco"
	Test-connection 
	pause
}

Function MatarProceso{
		Get-Process
		$pro=Read-host "Id del proceso a detener"
		stop-process $pro
}


Function GetEvent{
	$ruta="c:\users\Administrador\desktop\logs"
$date=read-host "Introduce una fecha para generar un log de eventos a partir de dicho dia: " 
$ruta2=$date.toString().substring(0,10).replace('/','-')
if(test-path $ruta){
	cd $ruta
}else{
	md $ruta
	cd $ruta
}
	if(test-path $ruta2){
		cd $ruta2
	}else{
		md $ruta2
		cd $ruta2
		
	}
	$nombre=$ruta2.toString()+"_sistema.txt"
	ni  $nombre -type file
	get-eventlog -logname system -entrytype error, warning -after $date |ft -wrap > $nombre
	$nombre=$ruta2.toString()+"_aplicacion.txt"
	ni  $nombre -type file
	get-eventlog -logname application -entrytype error, warning -after $date| ft -wrap > $nombre
	$nombre=$ruta2.toString()+"_hardware.txt"
	ni  $nombre -type file
	get-eventlog -logname hardwareevents -entrytype error, warning -after $date |ft -wrap > $nombre
	$nombre=$ruta2.toString()+"_seguridad.txt"
	ni  $nombre -type file
	get-eventlog -logname security -entrytype error, warning -after $date |ft -wrap > $nombre
	$nombre=$ruta2.toString()+"_powershell.txt"
	ni $nombre -type file
	get-eventlog -logname "windows powershell" -entrytype error, warning -after $date |ft -wrap > $nombre

$rutafin=$ruta+$ruta2
echo "Logs creados con éxito en "+$rutafin
pause
}


Function CrearEquipos{
Import-Module ActiveDirectory
$csvcontent = Import-CSV -Path c:\users\administrador\desktop\curro\Windows\Active_Directory\csvs\NewComputers.csv
foreach($computer in $csvcontent){
	New-ADComputer -name $computer.nombre -path $computer.unidadorganizativa
}


}


Function AbrirPuertos{
do{
	$puerto=Read-Host "Introduce el puerto que quieres abrir"
	$protocolo=Read-Host "Protocolo tcp o udp"
	
	
	if($protocolo -eq "tcp" -or $protocolo -eq "udp"){
		netsh advfirewall firewall add rule name="$puerto $protocolo" dir=in action=allow protocol=$protocolo localport=$puerto
		echo "Regla creada"
	}
	
	$r=Read-host "Quieres abrir otro puerto"


}while($r -eq "Si")

}



Function CerrarPuertos{
do{
	$puerto=Read-Host "Introduce el puerto que quieres cerrar"
	$protocolo=Read-Host "Protocolo tcp o udp"
	
	
	if($protocolo -eq "tcp" -or $protocolo -eq "udp"){
		netsh advfirewall firewall delete rule name="$puerto $protocolo"
		echo "Regla borrada"
	}
	
	$r=Read-host "Quieres cerrar otro puerto"


}while($r -eq "Si")

}

Function ListarPuertos {
	netstat -ano |findstr LIST
	netstat -ano |findstr ESTA
	pause
	
}


Function ListarPermisos{
	do{
	$f=Read-host "Introduce la ruta absoluta del directorio o fichero para ver sus permisos"
	Get-acl $f| fl -wrap
	$r=Read-host "Quieres comprobar los permisos de otro directorio o fichero"


}while($r -eq "Si")

}


Function CambiarPermisos{
	do{

	$ruta=Read-Host "Introduce el directorio al que se le cambiaran los permisos"
	$SoloLectura = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute"
	$LecturaEscritura = [System.Security.AccessControl.FileSystemRights]"Modify"

	$GrupoLe = Read-Host "Introduce el nombre del grupo que tendra derechos de lectura y escritura"
	$GrupoL = Read-Host "Introduce el nombre del grupo que tendra derechos de lectura "
	$inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"

	$propagationFlag = [System.Security.AccessControl.PropagationFlags]::None

	$userRW = New-Object System.Security.Principal.NTAccount($GrupoLe)
	$userR = New-Object System.Security.Principal.NTAccount($GrupoL)

	$type = [System.Security.AccessControl.AccessControlType]::Allow
	$accessControlEntryDefault = New-Object System.Security.AccessControl.FileSystemAccessRule @("Domain Users", $SoloLectura, $inheritanceFlag, $propagationFlag, $type)
	$accessControlEntryRW = New-Object System.Security.AccessControl.FileSystemAccessRule @($userRW, $LecturaEscritura, $inheritanceFlag, $propagationFlag, $type)
	$accessControlEntryR = New-Object System.Security.AccessControl.FileSystemAccessRule @($userR, $SoloLectura, $inheritanceFlag, $propagationFlag, $type)
	$objACL = Get-ACL $ruta
	$objACL.RemoveAccessRuleAll($accessControlEntryDefault)
	$objACL.AddAccessRule($accessControlEntryRW)
	$objACL.AddAccessRule($accessControlEntryR)
	Set-ACL  $ruta $objACL| ft -wrap
	$r=Read-host "Quieres cambiar los permisos de otro directorio o fichero"


}while($r -eq "Si")

}



Function ListarRecursoCompartido{
	get-smbshare |ft -wrap
	$recurso=Read-Host "Introduce el nombre de un recurso para saber sus permisos"
	get-smbshareaccess $recurso|ft -wrap
}

Function CrearRecursoCompartido{
do{
	$nombre=Read-Host "Inserta el nombre del recurso a compartir"
	$ruta=Read-Host "Inserta la ruta en la que se encuentre el recurso a compartir"
	new-smbshare -name $nombre -path $ruta 
	$r=Read-Host "Quieres compartir otro directorio"

}while($r -eq "Si")
}


Function BorrarRecursoCompartido{
do{
	$nombre=Read-Host "Inserta el nombre del recurso compartido a eliminar"
	remove-smbshare -name $nombre 
	$r=Read-Host "Quieres borrar otro directorio"
}while($r -eq "Si")
}



Function CambiarPermisosRecursoCompartido{
do{
	$nombre=Read-Host "Inserta el nombre del recurso compartido al que quieres cambiar los permisos"
	$grupo=Read-Host "Inserta el nombre del grupo al que quieres cambiar los permisos"
	$permisos=Read-Host "Full,Change,Read o Custom"
	grant-smbshareaccess -name $nombre -AccountName -AccessRights $permisos
	$r=Read-Host "Quieres cambiar los permisos de otro recurso"
}while($r -eq "Si")
}




Function QuitarPermisosRecursoCompartido{
do{
	$nombre=Read-Host "Inserta el nombre del recurso compartido al que quieres quitarle permisos"
	$grupo=Read-Host "Inserta el nombre del grupo al que quieres quitar los permisos"
	revoke-smbshareaccess -name $nombre -AccountName 
	$r=Read-Host "Quieres quitar los permisos de otro recurso"
}while($r -eq "Si")
}


Function ListarEquipos{
	get-AdComputer -filter * |select distinguishedname
	pause
}






Function Get-Menu{
write-host ""
$ruta=get-location
echo "Estas en $ruta"
write-host ""
Write-Host "Que quieres hacer"
Write-host "1.- Crear Directorio"
Write-host "2.- Borrar Directorio"
Write-Host "3.- Crear Fichero"
Write-Host "4.- Borrar Fichero"
Write-Host "5.- Ver Fichero"
Write-Host "6.- Listar Directorios"
Write-Host "7.- Cambiar Directorio"
Write-Host "8.- Crear Varios Usuarios en Active Directory"
Write-host "9.- Crear Grupos Active Directory"
Write-host "10.- Unir Usuarios a grupos de Active Directory"
Write-host "11.- Borrar Usuarios de Active Directory"
Write-host "12.- Listar Usuarios de Active Directory"
Write-host "13.- Borrar grupos de Active Directory"
Write-host "14.- Eliminar Usuarios de grupos en Active Directory"
Write-host "15.- Listar grupos de Active Directory"
Write-host "16.- Listar usuarios de un grupo de Active Directory"
Write-host "17.- Crear Unidades Organizativas"
Write-host "18.- Borrar Unidades Organizativas"
Write-host "19.- Listar Unidades Organizativas"
Write-host "20.- Descargar ayuda de comandos"
Write-host "21.- Cambiar password a un usuario"
Write-host "22.- Cambiar password a varios usuarios"
Write-host "23.- Exportar gpos"
Write-host "24.- Ver Envio de paquetes a una Ip o Dominio"
Write-host "25.- Matar Proceso"
Write-host "26.- Generar Eventos de todos los tipos (errores y advertencias)"
Write-host "27.- Crear equipos"
Write-host "28.- Listar equipos"
Write-host "29.- Abrir Puerto"
Write-host "30.- Cerrar Puerto"
Write-host "31.- Lista Puertos"
Write-host "32.- Listar Permisos"
Write-host "33.- Cambiar Permisos"
Write-host "34.- Listar Recursos Compartidos"
Write-host "35.- Crear Recurso Compartido"
Write-host "36.- Eliminar Recurso Compartido"
Write-host "37.- Cambiar Permisos Recurso Compartido"
Write-host "38.- Quitar Permisos Recurso Compartido"
Write-Host "50.- Salir"
}

do{
Get-Menu
write-host ""
$opcion = Read-Host "Elija una opcion"
switch ($opcion){
'1'{CrearDirectorio}
'2'{BorrarDirectorio}
'3'{CrearFichero}
'4'{BorrarFichero}
'5'{VerFichero}
'6'{ListarDirectorios}
'7'{CambiarDirectorio}
'8'{CrearusuariosAd}
'9'{CrearGruposAd}
'10'{UnirusuariosAGrupos}
'11'{BorrarusuariosAd}
'12'{ListarUsuariosAd}
'13'{BorrarGruposAd}
'14'{EliminarusuariosDeGruposAD}
'15'{ListarGruposAd}
'16'{UsuariosDeUnGrupo}
'17'{CrearUO}
'18'{BorrarUO}
'19'{ListarUO}
'20'{Ayuda}
'21'{CambiarPasswordaUsuario}
'22'{CambiarPasswordaVariosuarios}
'23'{ExportarGPOS}
'24'{TestConnection}
'25'{MatarProceso}
'26'{GetEvent}
'27'{CrearEquipos}
'28'{ListarEquipos}
'29'{AbrirPuertos}
'30'{CerrarPuertos}
'31'{ListarPuertos}
'32'{ListarPermisos}
'33'{CambiarPermisos}
'34'{ListarRecursoCompartido}
'35'{CrearRecursoCompartido}
'36'{BorrarRecursoCompartido}
'37'{CambiarPermisosRecursoCompartido}
'38'{QuitarPermisosRecursoCompartido}
'50'{Salir}
}
}while ($true)




