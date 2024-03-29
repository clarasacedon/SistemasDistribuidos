# Template project for ssdd-lab

This repository is a Python project template.
It contains the following files and directories:

- `configs` has several configuration files examples.
- `iceflix` is the main Python package.
  You should rename it to something meaninful for your project.
- `iceflix/__init__.py` is an empty file needed by Python to
  recognise the `iceflix` directory as a Python module.
- `iceflix/cli.py` contains several functions to handle the basic console entry points
  defined in `python.cfg`.
  The name of the submodule and the functions can be modified if you need.
- `iceflix/iceflix.ice` contains the Slice interface definition for the lab.
- `iceflix/main.py` has a minimal implementation of a service,
  without the service servant itself.
  Can be used as template for main or the other services.
- `pyproject.toml` defines the build system used in the project.
- `run_client` should be a script that can be run directly from the
  repository root directory. It should be able to run the IceFlix
  client.
- `run_service` should be a script that can be run directly from the
  repository root directory. It should be able to run all the services
  in background in order to test the whole system.
- `setup.cfg` is a Python distribution configuration file for Setuptools.
  It needs to be modified in order to adeccuate to the package name and
  console handler functions.

# Ejecución

1. Abrir una terminal, posicionarnos en la carpeta principal del proyecto ("DISTRIBUIDOS") y ejecutar el comando `./run_icestorm`.
2. Abrir una terminal nueva, independiente de la anterior, y ejecutar el comando `./run_service`.
3. Podemos probar a abrir otra terminal y volver a ejecutar `./run_service` para simular que hay varios servicios Authenticathor y ver como se reconocen entre ellos.

**¡!** Es importante mirar que los archivos "*iceflix/authenticator.py*", "*run_icestorm*" y "*run_service*" tengan los permisos adecuados. Si no es así, podemos concedérselos por comando o a través de la interfaz gráfica:  
***archivo \> propiedades > permisos \> "Programa: Permitir que este archivo se ejecute com programa"***