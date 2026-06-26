# SecAgent Nmap

## Descripción

SecAgent Nmap es un agente local de reconocimiento automatizado desarrollado en Python para entornos de laboratorio de ciberseguridad. Su objetivo es combinar el escaneo técnico de Nmap con el análisis asistido por un modelo LLM local ejecutado mediante Ollama.

El script recibe una solicitud en lenguaje natural, identifica la dirección IP objetivo y determina el tipo de análisis requerido. Independientemente de la solicitud, Nmap ejecuta un escaneo completo de todos los puertos TCP abiertos con detección de servicios y versiones. Posteriormente, Python procesa la salida XML de Nmap, clasifica los servicios encontrados y filtra los resultados según la intención del usuario.

El agente puede enfocar el análisis en distintas categorías, como servicios web, bases de datos, administración remota, SMB, FTP, correo, DNS o realizar un análisis completo de todos los servicios detectados. Luego, el modelo LLM analiza únicamente los servicios correspondientes a la categoría solicitada, evitando interpretar puertos que no forman parte del alcance definido.

El resultado final entrega un reporte técnico con los puertos abiertos detectados, servicios identificados, versiones, categorías asociadas, riesgos potenciales, prioridad sugerida y pasos defensivos recomendados.

Este proyecto está orientado a prácticas académicas, pruebas controladas y laboratorios propios de ciberseguridad. No debe utilizarse contra sistemas de terceros sin autorización expresa.

Ejemplo de comandos de prueba con el modelo “dolphincoder:latest”, este se puede modificar directamente en el script.
<img width="827" height="365" alt="image" src="https://github.com/user-attachments/assets/ad0ba8e6-93fc-4edd-88d1-f7641986e4fa" />

python secagentV4_nmap.py "Verifica los servicios web de 10.10.1.129"
<img width="827" height="564" alt="image" src="https://github.com/user-attachments/assets/e8318ba3-7ecd-4fd1-b7e7-769af9e5d9d0" />
<img width="827" height="556" alt="image" src="https://github.com/user-attachments/assets/99f3ec94-fd17-4b1b-bc3b-574ee2da9375" />

