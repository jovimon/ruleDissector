#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
ruleDissector.py

@author: @j0sm1
@author: @jovimon
@version: 0.1.20131001

Parsea la configuración de Snort para encontrar todas las reglas activas, y las guarda en una variable, 
para luego realizar modificaciones sencillas o sacar estadísticas.

TODO:
 - Enlazar modificadores con argumento. Por ejemplo: content:".php?w="; depth: 1;
 - Controlar existencia de 2+ argumentos con el mismo nombre en las funciones get/set.

'''

import re

class rulesetParser():
    '''
    Clase para cargar un ruleset activo en memoria para su posterior tratamiento
    '''
        
    def __init__(self, basedir = '/usr/local/snort/etc', snortfile = 'snort.conf', classiffile = 'classification.config', rulesdir = 'rules'):
        '''
        Constructor of object
        '''
        self.base_dir = basedir
        self.snort_file = snortfile
        self.classif_file = classiffile
        self.rules_dir = rulesdir
        self.included_files = []
        self.included_files.append(self.snort_file)
        self.rule_files = []
        self.classification = {}
        self.ruleset = []
        #self.printArgs()
        self.searchRuleFiles()
        self.loadClassification()
        self.readRules()

    def printArgs(self):
        '''
        Imprime los argumentos que se le pasan a la clase
        '''
        print self.base_dir
        print self.snort_file
        print self.classif_file
        print self.rules_dir
        print

    def searchForIncludes(self, fichero):
        '''
        Lee un fichero en busca de otros ficheros incluidos, ya sean otros ficheros 
        de configuración (salvados en included_files) o ficheros de reglas (salvados
        en rule_files)
        '''
        f = open(fichero, 'r')
        fichero = f.readlines()
        # Relleno los ficheros incluidos. No necesito resolver variables porque la única que me interesa la tengo por parámetro.
        for linea in fichero:
            if linea.find('include') == 0:
                aux = linea.split()
                if aux[1].find('$RULE_PATH') == 0:
                    if aux[1].find('.rules') != -1: 
                        self.rule_files.append(self.rules_dir + '/' + aux[1][11:])
                    else:
                        self.included_files.append(self.rules_dir + '/' + aux[1][11:])
                else:
                    if aux[1].find('.rules') == len(aux[1]) - 6:
                        self.rule_files.append(aux[1])
                    else:
                        self.included_files.append(aux[1])

    def searchRuleFiles(self):
        '''
        Lee todos los ficheros incluidos a partir del fichero snort.conf
        '''
        for fichero in self.included_files:
            self.searchForIncludes(self.base_dir + '/' + fichero)
        #print self.included_files
        #print
        #print self.rule_files
        #print

    def loadClassification(self):
        '''
        Carga la correspondencia clasificación - prioridad del fichero de clasificaciones.
        '''
        f = open(self.base_dir + '/' + self.classif_file, 'r')
        fichero = f.readlines()
        for linea in fichero:
            if linea.find('config classification') == 0:
                # linea[:-1] quita el \n del final de cada linea
                # split(':')[1] divide por el caracter ':' y devuelve el segundo segmento
                # split(',') divide el resultado del paso anterior por el caracter ','
                aux = linea[:-1].split(':')[1].split(',')
                self.classification[aux[0].strip()] = aux[2]
        #print self.classification 
        #print

    def readRules(self):
        '''
        Lee las reglas de los ficheros que hemos obtenido
        '''
        for fichero in self.rule_files:
            f = open(self.base_dir + '/' + fichero, 'r')
            fichero = f.readlines()
            for linea in fichero:
                regla = ruleDissector().parseRule(linea)
                if regla != None:
                    aux = regla.getClasstype()
                    if aux != None:
                        aux = aux.strip()
                        regla.addArgument('priority', self.classification[aux].strip())
                    self.ruleset.append(regla)

        print str(len(self.ruleset)) + " reglas leidas"




class ruleDissector():
    '''
    Clase para manipular todos los campos de una regla de Snort de una manera sencilla
    '''
        
    def __init__(self):
        '''
        Constructor of object
        '''
        self.accion = ''
        self.protocolo = ''
        self.srcnet = ''
        self.srcport = ''
        self.direction = '->'
        self.dstnet = ''
        self.dstport = ''
        self.argumentos = []
	self.origString = ''
    
    def parseRule(self,ruleString):
        '''
        Parse ruleString and init structure data
        '''
	self.origString = ruleString
        acciones_validas = ['alert']
        protocolos_validos = ['tcp','udp','ip','icmp']
        
        options = ruleString.split()

        if len(options) == 0:
            return None
        
        if options[0] in acciones_validas:
            self.accion = options[0]
        else:
            return None
        
        if options[1] in protocolos_validos:
            self.protocolo = options[1]
        else:
            return None
        
        self.srcnet = options[2]
        self.srcport = options[3]
        self.direction = options[4]
        self.dstnet = options[5]
        self.dstport = options [6]
        
        params = re.findall('([(].+[)])',ruleString)
        argum = re.findall('([a-zA-Z:]+[^;]+;)',params[0])
        
        for a in argum:
            aux = []
            a = a.strip()
            pre = re.findall('[a-zA-Z]+:',a)
            if pre == []:
                anterior = self.argumentos.pop()
                aux = anterior.pop()
                aux = aux + "; " + a.strip(";")
                anterior.append(aux)
                self.argumentos.append(anterior)
                continue
            suf = a[len(pre[0]):].strip()
            aux.append(pre[0].strip(":"))
            aux.append(suf.strip(";"))
            self.argumentos.append(aux)

        return self
    
    def getSid(self):
        '''
            Get sid of Snort Rule
            @return: value of argument sid
        '''
        for arg in self.argumentos:
            if arg[0] == "sid":
                return arg[1]
            
    def getClasstype(self):
        '''
            Get classtype of Snort Rule
            @return: value of argument classtype
        '''
        for arg in self.argumentos:
            if arg[0] == "classtype":
                return arg[1]
    
    def getMsg(self):
        '''
            Get msg of Snort Rule
            @return: value of argument msg
        '''
        for arg in self.argumentos:
            if arg[0] == "msg":
                return arg[1]
            
    def getRev(self):
        '''
            Get revision of Snort Rule
            @return: value of argument rev
        '''
        for arg in self.argumentos:
            if arg[0] == "rev":
                return arg[1]
    
    def setMsg(self, newmsg):
        '''
            Set message value in Snort Rule
        '''
        for arg in self.argumentos:
            if arg[0] == "msg":
                arg[1] = newmsg
    
    def setSid(self, newsid):
        '''
            Set sid value in Snort Rule
        '''
        for arg in self.argumentos:
            if arg[0] == "sid":
                arg[1] = newsid
    
    def setRev(self, newrev):
        '''
            Set rev value in Snort Rule
        '''
        for arg in self.argumentos:
            if arg[0] == "rev":
                arg[1] = newrev
                
    def getArgument(self,argumento):
        '''
            Get argument value of Snort Rule
            @argumento: argument to get
        '''
        for arg in self.argumentos:
            if arg[0] == argumento:
                return arg[1]
            
    def setArgument(self,argumento,valor):
        '''
            Set argument value in Snort Rule
            @argumento: argument to set in rule 
            @value: value to set in rule
        '''
        for arg in self.argumentos:
            if arg[0] == argumento:
                arg[1] = valor
    
    def addArgument(self, nombre, valor):
        '''
            Add new argument value to the Snort Rule
            @nombre: new argument to set in rule 
            @value: new value to set in rule
        '''
        arg = []
        arg.append(nombre)
        arg.append(valor)
        self.argumentos.append(arg)
    
    def createRule(self):
        '''
            Create a String from a ruleDissector object
            @return: rule string
        '''
        argument = ''
        for arg in self.argumentos:
            argument = argument + ": ".join(arg) + "; "
        
        inicio = self.accion + " " + self.protocolo + " " + self.srcnet + " " + self.srcport + " " + self.direction + " " + self.dstnet + " " + self.dstport + " " + "("
        fin = ")"
        reglanueva = inicio + argument + fin
        return reglanueva