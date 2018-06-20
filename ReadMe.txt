
Autor: David Abreu Canamares

Proyecto: Desarrollo de un sistema de detección de tráfico anómalo en redes SCADA basadas en el protocolo IEC 60870-5-104


Entrega: 
	5 archivos programados en Python:
		- sniff.py
			Este archivo es capaz de analizar la red en tiempo real
		- speed.py
			Este archivo se utiliza para analizar trazas rápidamente
		-prueba.py
			Este archivo se utiliza para anlizar trazas pequenas y probar el IDS
		-real.py
			Este archivo es capaz de analizar cualquier tamano de trazas y crea los archivos correspondientes en su análisis
		-iec104lib.py
			Librería del IEC 60870-5-104

	1 archivo en Pypy:
		-speedpypy.py
			Misma función que el archivo speed.py pero se ejecuta con Pypy

	1 archivo de configuración:
		-config.ini
			Este archivo sirve para configurar que traza se desea analizar o que interfaz se desea capturar
