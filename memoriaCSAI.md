## Fase 1: Pentesting y Obtención de Acceso 

Una vez desplegada la máquina virtual, lo primero que realizamos es un nmap para escanear la máquina y descubrir los servicios y puertos abiertos. Encontramos dos puertos abiertos:

- Puerto 22: SSH.
- Puerto 80: HTTP.

![Nmap](A_Docs/nmap.png)

Al intentar acceder por HTTP, nos encontramos que hay una redirección a norc.labs. Para poder seguirla y que se resuelva correctamente la petición, tenemos que actualizar nuestro /etc/hosts añadiendo una nueva entrada:

![Norc Labs](A_Docs/norclabs.png)

Una vez actualizado el fichero, accedemos y encontramos una página de login en el que nos deja introducir una contraseña. Podríamos usar algún método de fuerza bruta para obtenerla ya que no hay un límite de intentos, pero buscamos otra solución.

Usamos la herramienta gobuster para ver qué otros directorios hay en la página. El comando es el siguiente: 

```bash
gobuster dir -u http://norc.labs -w /usr/share/wordlists/dirb/common.txt -t 50 -b 404,302

```

Lo ejecutamos sobre la URL con una wordlist por defecto de gobuster y buscamos archivos php, html o txt. Además, ignoramos las respuestas que devuelvan un 404 o 302. Los directorios más interesantes que obtenemos son los siguientes:

![Gobuster](A_Docs/gobuster.png)

 Son directorios comunes en Wordpress, por lo que ya tenemos más información sobre la página. Si accedemos a wp-admin, vemos que es una página de login de wordpress, pero aquí no podemos aplicar fuerza bruta para la contraseña ya que solo hay 3 intentos para introducirla. Pero sabiendo que es un wordpress, ya tenemos la información de que existe una base de datos y seguramente algún plugin que pueda ser vulnerable. 

Empezamos por buscar algún plugin. Buscamos algún fichero en internet que contenga una wordlist con plugins comunes en wordpress, y los usamos junto a la herramienta ffuf para ir probando y ver cuáles encontramos. Tras probar varias wordlists distintas, con una de ellas obtenemos el siguiente resultado:

```bash
ffuf -u http://norc.labs/FUZZ -w plugins.txt -fs 0 -fc 403
```

![Ffuf](A_Docs/ffuf.png)


Podemos ver que está corriendo (Status 200) el plugin de wp-fastest-cache, e investigando sobre sus posibles vulnerabilidades encontramos que es sensible a sql injection.  Es vulnerable a la inyección en una cookie mediante el siguiente comando:

```bash
sqlmap --dbms=mysql -u "http://norc.labs/wp-login.php" --cookie='wordpress_logged_in=*' --level=2 --schema
```

Obtenemos como salida es esquema general, con dos bases de datos:

- information_schema
- wordpress

La que nos interesa es la segunda, para ver si podemos obtener de alguna forma el usuario o la contraseña de algún usuario. Ejecutamos ahora el comando pero sobre la base de datos wordpress:

```bash
sqlmap -u "http://norc.labs/wp-login.php" --cookie="wordpress_logged_in=*" --dbms=mysql --level=2 --tables -D wordpress
```

La salida que obtenemos son todas las tablas de esa base de datos:

![Base de datos](A_Docs/db_gen.png)

La que más nos interesa es la tabla de wp_users, ya que es donde podemos obtener los datos para acceder a la página de wordpress. Ejecutamos el comando para obtener los datos de esa tabla:

```bash
sqlmap -u "http://norc.labs/wp-login.php" --cookie="wordpress_logged_in=*" --dbms=mysql --dump -D wordpress -T wp_users
```

![Base de datos](A_Docs/db.png)

Obtenemos el usuario, su correo electrónico y también la contraseña, aunque hasheada, por lo que no nos sirve para acceder.

Aún así, podemos ver que el email pertenece al dominio "oledockers.norc.labs". Lo visitamos y vemos que no resuelve la petición, por lo que lo metemos también en el /etc/hosts. Al acceder, vemos que es una bandeja de entrada con un mensaje en el que podemos obtener el usuario y su contraseña, obteniendo acceso al wordpress.

![Inbox](inbox.png)

Una vez dentro de WordPress, tendremos acceso a varias funcionalidades. Entre ellas se encuentra la edición de los archivos del theme, los cuales contienen código en PHP, HTML, CSS y JavaScript, y determinan cómo se muestra y funciona el sitio web. Esta opción permite modificar el comportamiento del sitio de manera legítima, pero también puede ser aprovechada con fines maliciosos.

Si un atacante logra acceder al panel de administración, puede editar archivos clave del tema, como el index.php del theme Twenty Twenty-Two, para insertar código malicioso. A través de esta modificación, es posible ejecutar comandos en el servidor, establecer conexiones remotas o incluso crear una puerta trasera para acceder al sitio de manera persistente.

Establecemos un shell inverso que nos permite atraves de una llamada http conectarnos a la maquína.

Una vez dentro de la máquina, nos encontraremos ejecutando comandos con el usuario www-data, que es el usuario por defecto de servidores web como Apache y Nginx. Este usuario tiene permisos limitados dentro del sistema, lo que restringe nuestras acciones y evita que podamos modificar archivos críticos o ejecutar comandos con privilegios elevados.

El primer paso será explorar los distintos archivos y directorios en busca de información sensible o posibles vulnerabilidades. Para ello, revisaremos los permisos, propietarios y configuraciones de archivos clave que puedan darnos acceso a otros usuarios o procesos con más privilegios. Centraremos nuestra atención en el directorio /home/kvlz, ya que pertenece a otro usuario que probablemente tenga más permisos que www-data.

Al analizar el sistema, encontramos un script llamado cron_script.sh dentro del directorio del usuario kvlz. Observamos que su función principal es leer el contenido de un archivo llamado wp-encrypted.txt, el cual está cifrado en Base64, luego desencriptarlo y volcar el resultado en /tmp/decoded.txt.

Este comportamiento sugiere que el script se ejecuta de manera automática en intervalos de tiempo, posiblemente a través de una tarea programada con cron.

Dado que el archivo wp-encrypted.txt no existe en el sistema, podemos aprovechar la situación para crear nuestro propio archivo. La idea es escribir el código que, al ser descifrado por el script, permita establecer un shell inverso en el puerto 1234. Una vez que se tenga el comando o secuencia de comandos necesaria, se procede a cifrarlo en Base64 para que, al ejecutarse el script y se decodifique. Desde otro terminal esperamos a que el payload se ejecute y tendremos acceso a la máquina con el usuario kvzlx.

Al investigar los archivos en el sistema, no encontramos binarios con permisos inusuales que pudieran explotarse directamente para la escalada de privilegios. Sin embargo, observamos que en el directorio /opt está instalada una versión de Python, lo que podiamos intuir, ya que en el análisis con la herramienta pspy, notamos que los permisos de ejecución de Python fueron retirados para el usuario www-data.

Centrandonos en pyhon procedemos a utilizar la herramienta getcap para analizar las capabilities. Un mecanismo de control de privilegios en sistemas operativos basados en Unix que permite dividir los privilegios del superusuario (root) en distintas “capacidades” independientes.

Como no podemos instalar la herramienta directamente en la maquina vulnerable lo que haremos es crear un servidor que corra en el puerto 8080 y ofrezca lso binarios necesarios 