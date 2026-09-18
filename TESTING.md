# Verificación 0.2.0

- Compilación release Windows x64 aprobada.
- Tres pruebas Rust aprobadas: validación de servidores y estados, reportes y timeout.
- Pruebas Windows PowerShell 5.1 aprobadas: sintaxis, discovery, tamaño de backup, ACL, volumen inaccesible, falta de espacio (FAIL), TEMP insuficiente (WARN), búsqueda automática del fix, versión superior, versión igual y rama incompatible.
- Ya no existen campos de entrada para rutas, dominio o versión objetivo. Los parámetros serializados tampoco contienen esas opciones.
- Se validan todas las instalaciones descubiertas; la unidad de backup se deriva de cada instalación.

No se probaron servidores remotos ni una instalación real de Connect:Direct. La revisión visual automática no estuvo disponible: Computer Use agotó el tiempo de espera al enumerar ventanas. Los resultados del diagnóstico local del ejecutable están en la carpeta Reportes de esta entrega.
