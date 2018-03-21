// Copyright 2017 Apigee
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"io"
	"log"
	"path/filepath"
	"strings"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/apimachinery/pkg/util/yaml"
	res "k8s.io/apimachinery/pkg/api/resource"
	yml "github.com/ghodss/yaml"
)

var org, env, username, password, configFile, key, scrt, mgmturl, mgVer string
var configFileData []byte
var fileerr error
const version string = "1.0.0"

var infoLogger bool

var (
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

func Init(
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func createSecret() v1.Secret {
	secret := v1.Secret{}
	secret.APIVersion = "v1"
	secret.Kind = "Secret"
	datamap := make(map[string][]byte)
	datamap["mgorg"] = ([]byte(org))
	datamap["mgenv"] = ([]byte(env))
	datamap["mgkey"] = ([]byte(key))
	datamap["mgsecret"] = ([]byte(scrt))
	datamap["mgconfig"] = []byte(b64.StdEncoding.EncodeToString(configFileData))
	if mgmturl != "" {
		datamap["mgmgmturl"] = ([]byte(mgmturl))
	} else {
		//The default management url is cloud endpoint
		datamap["mgmgmturl"] = ([]byte("https://api.enterprise.apigee.com"))
	}
	datamap["mgadminemail"] = ([]byte(username))
	datamap["mgadminpassword"] = ([]byte(password))
	secret.Name = "mgwsecret"
	secret.Type = "Opaque"
	secret.Data = datamap
	return secret
}

func printSecret(secret v1.Secret) {
        jsonsecret, _ := json.Marshal(&secret)
        yamlout, _ := yml.JSONToYAML(jsonsecret)
        fmt.Printf(string(yamlout))
        fmt.Println("---")
}

func getResources() v1.ResourceRequirements {
	resources := v1.ResourceRequirements{}
	limits := v1.ResourceList{}
	requests := v1.ResourceList{}

	limits["cpu"] = getQuantity(1, true)
	limits["memory"] = getQuantity(2*1024*1024*1024, false) //"2048Mi"

	requests["cpu"] = getQuantity(1, true)
	requests["memory"] = getQuantity(1*1024*1024*1024, false) //"1024Mi"

	resources.Limits = limits
	resources.Requests = requests
	return resources
}

func getQuantity(unit int64, decimal bool) res.Quantity {
	var quantity *res.Quantity
	if decimal == true {
		quantity = res.NewQuantity(unit, res.DecimalSI)
	} else {
		quantity = res.NewQuantity(unit, res.BinarySI)
	}
	return *quantity
}

func createContainer() v1.Container {
	container := v1.Container{}
	port := v1.ContainerPort{}
	port.ContainerPort = 8000
	container.Name = "edge-microgateway"
	container.Image = "docker.io/edgemicrok8/edgemicro:" + mgVer
	container.Ports = append(container.Ports, port)
	container.Env = append(container.Env, createEnv("EDGEMICRO_ORG","mgwsecret", "mgorg"))
	container.Env = append(container.Env, createEnv("EDGEMICRO_ENV","mgwsecret", "mgenv"))
	container.Env = append(container.Env, createEnv("EDGEMICRO_KEY","mgwsecret", "mgkey"))
	container.Env = append(container.Env, createEnv("EDGEMICRO_SECRET","mgwsecret", "mgsecret"))
	container.Env = append(container.Env, createEnv("EDGEMICRO_CONFIG","mgwsecret", "mgconfig"))
	container.Env = append(container.Env, createEnv("EDGEMICRO_MGMTURL","mgwsecret", "mgmgmturl"))
	container.Env = append(container.Env, createEnv("EDGEMICRO_ADMINEMAIL","mgwsecret", "mgadminemail"))
	container.Env = append(container.Env, createEnv("EDGEMICRO_ADMINPASSWORD","mgwsecret", "mgadminpassword"))
	container.Env = append(container.Env, createEnvVal("EDGEMICRO_DECORATOR", "1"))
	container.Env = append(container.Env, createEnvVal("EDGEMICRO_CONFIG_DIR","/opt/apigee/.edgemicro"))
	container.Env = append(container.Env, createEnvValField("POD_NAME","metadata.name"))
	container.Env = append(container.Env, createEnvValField("POD_NAMESPACE","metadata.namespace"))
	container.Env = append(container.Env, createEnvValField("SERVICE_NAME","metadata.labels['app']"))
	container.Env = append(container.Env, createEnvValField("INSTANCE_IP","status.podIP"))
	container.ImagePullPolicy = "Always"
	container.Resources = getResources()
	return container
}

func createInitContainer1() v1.Container {
	container := v1.Container{}
	container.Name = "edgemicro-apigee"
	container.Image = "docker.io/edgemicrok8/edgemicro_apigee_setup:" + mgVer
	container.Env = append(container.Env, createEnv("EDGEMICRO_ORG","mgwsecret", "mgorg"))
        container.Env = append(container.Env, createEnv("EDGEMICRO_ENV","mgwsecret", "mgenv"))
        container.Env = append(container.Env, createEnv("EDGEMICRO_KEY","mgwsecret", "mgkey"))
        container.Env = append(container.Env, createEnv("EDGEMICRO_SECRET","mgwsecret", "mgsecret"))
        container.Env = append(container.Env, createEnv("EDGEMICRO_CONFIG","mgwsecret", "mgconfig"))
        container.Env = append(container.Env, createEnv("EDGEMICRO_MGMTURL","mgwsecret", "mgmgmturl"))
        container.Env = append(container.Env, createEnv("EDGEMICRO_ADMINEMAIL","mgwsecret", "mgadminemail"))
        container.Env = append(container.Env, createEnv("EDGEMICRO_ADMINPASSWORD","mgwsecret", "mgadminpassword"))
        container.Env = append(container.Env, createEnvVal("EDGEMICRO_DECORATOR", "1"))
        container.Env = append(container.Env, createEnvVal("EDGEMICRO_CONFIG_DIR","/opt/apigee/.edgemicro"))
	container.Env = append(container.Env, createEnvVal("EDGEMICRO_CREATE_PRODUCT","1"))
	container.Env = append(container.Env, createEnvValField("POD_NAME","metadata.name"))
	container.Env = append(container.Env, createEnvValField("POD_NAMESPACE","metadata.namespace"))
        container.Env = append(container.Env, createEnvValField("SERVICE_NAME","metadata.labels['app']"))
        container.Env = append(container.Env, createEnvValField("INSTANCE_IP","status.podIP"))
	container.ImagePullPolicy = "Always"
	container.SecurityContext = createSecContext()
	return container
}

func createInitContainer2() v1.Container {
	container := v1.Container{}
	var args = []string{"-p","8000","-u","1001"}
	container.Name = "edgemicro-init"
	container.Image = "docker.io/edgemicrok8/edgemicro_proxy_init:latest"
	container.Args = args
	container.ImagePullPolicy = "Always"
	container.SecurityContext = createSecContext()
	return container
}

func createSecContext() *v1.SecurityContext {
	secContext := v1.SecurityContext{}
        secContext.Capabilities = createCapabilities()
	return &secContext
}

func createCapabilities() *v1.Capabilities {
	capabilities := v1.Capabilities{}
        capabilities.Add = append(capabilities.Add, "NET_ADMIN")
	return &capabilities
}

func getInitContainers() []v1.Container {
	var containers []v1.Container
	containers = append(containers, createInitContainer1())
	containers = append(containers, createInitContainer2())
	return containers
}


func createEnv(name string, refname string, refkey string) v1.EnvVar {
	env := v1.EnvVar{}
	env.Name = name
	env.ValueFrom = createEnvVarSource(refname, refkey)
	return env
}

func createEnvVal(name string, value string) v1.EnvVar {
	env := v1.EnvVar{}
	env.Name = name
	env.Value = value
	return env
}

func createEnvValField(name string, fieldpath string) v1.EnvVar {
	env := v1.EnvVar{}
	env.Name = name
	env.ValueFrom = createEnvVarSource2(fieldpath)
	return env
}

func createEnvVarSource (refname string, refkey string) *v1.EnvVarSource {
	envvar := v1.EnvVarSource{}
	envvar.SecretKeyRef = createSecretKeyRef(refname, refkey)
	return &envvar
}

func createEnvVarSource2(fieldpath string)  *v1.EnvVarSource {
	envvar := v1.EnvVarSource{}
	envvar.FieldRef = createFieldRef(fieldpath)
	return &envvar
}

func createFieldRef(fieldpath string) *v1.ObjectFieldSelector {
	fieldsel := v1.ObjectFieldSelector{}
	fieldsel.FieldPath = fieldpath
	return &fieldsel
}

func createSecretKeyRef(refname string, refkey string) *v1.SecretKeySelector {
	secretkey := v1.SecretKeySelector{}
	secretkey.Name = refname
	secretkey.Key = refkey
	return &secretkey
}

func recurse(yamlDecoder io.ReadCloser, reader *os.File, yamlData []byte) {

	// Create decoding function used for YAML to JSON decoding
        decode := scheme.Codecs.UniversalDeserializer().Decode

	// Read first resource - expecting deployment with size < 2048
	yamlData = make([]byte, 1024)
	_, err := yamlDecoder.Read(yamlData)
        if err != nil {
               return 
        }


	// Trim unnecessary trailing 0x0 signs which are not accepted
	trimmedYaml := strings.TrimRight(string(yamlData), string(byte(0)))
	t := strings.TrimSpace(trimmedYaml)

	if t != "" {} else {return}

	// Decode deployment resource from YAML to JSON
	jsonData, _, err := decode([]byte(trimmedYaml), nil, nil)
        if err != nil {
                panic(err)
        }

	// Check "kind: deployment"
    if jsonData.GetObjectKind().GroupVersionKind().Kind != "Deployment" {
		out, _ := json.Marshal(jsonData)
		yamlout, _ := yml.JSONToYAML(out)
		fmt.Println(string(yamlout))
		fmt.Println("---")
		
    } else {
        // Marshall JSON deployment
		d, err := json.Marshal(&jsonData)
		if err != nil {
			panic(err)
		}

		// Unmarshall JSON into deployment struct
		var deployment appsv1beta1.Deployment
		err = json.Unmarshal(d, &deployment)
		if err != nil {
			panic(err)
		}

		deployment.Spec.Template.Spec.Containers = append(deployment.Spec.Template.Spec.Containers, createContainer())
		deployment.Spec.Template.Spec.InitContainers = getInitContainers()
		newDeployment, _ := json.Marshal(&deployment)
		yamlout, _ := yml.JSONToYAML(newDeployment)
		fmt.Printf(string(yamlout))
		fmt.Printf("\n---\n")
		
	}
	recurse(yamlDecoder, reader, yamlData)
		
		
}

func usage(message string) {
        fmt.Println("")
        if message != "" {
                fmt.Println("Incorrect or incomplete parameters, ", message)
        }
        fmt.Println("edgemicroctl version ", version)
        fmt.Println("")
        fmt.Println("Usage: edgemicroctl -org=<orgname> -env=<envname> -user=<username> -pass=<password> -conf=<conf file>")
        fmt.Println("")
        fmt.Println("Options:")
        fmt.Println("org  = Apigee Edge Organization name (mandatory)")
        fmt.Println("env  = Apigee Edge Environment name (mandatory)")
        fmt.Println("user = Apigee Edge Username (mandatory)")
        fmt.Println("pass = Apigee Edge Password (mandatory)")
        fmt.Println("key  = Apigee Edge Microgateway Key (mandatory)")
        fmt.Println("sec  = Apigee Edge Microgateway Secret (mandatory)")
        fmt.Println("conf = Apigee Edge Microgateway configuration file (mandatory)")
        fmt.Println("svc  = Kubernetes Service configuration file (mandatory)")
        fmt.Println("")
        fmt.Println("Other options:")
        fmt.Println("murl   = Apigee Edge Management API Endpoint; Default is api.enterprise.apigee.com")
        fmt.Println("debug  = Enable debug mode (default: false)")
        fmt.Println("")
        fmt.Println("")
        fmt.Println("Example: edgemicroctl -org=trial -env=test -user=trial@apigee.com -pass=Secret123 -config=trial-test-config.yaml")
        os.Exit(1)
}

func checkParams(org, env, username, password, configFile string) {
        if org == "" {
                usage("orgname cannot be empty")
        } else if env == "" {
                usage("envname cannot be empty")
        } else if username == "" {
                usage("username cannot be empty")
        } else if password == "" {
                usage("password cannot be empty")
        } else if configFile == "" {
                usage("configFile cannot be empty")
        } else if key == "" {
                usage("key cannot be empty")
        } else if scrt == "" {
                usage("secret cannot be empty")
        }
	if mgVer == "" {
		mgVer = "latest"
	}
}

func main() {

	var svcFile string
	flag.StringVar(&org, "org", "", "Apigee Organization Name")
        flag.StringVar(&env, "env", "", "Apigee Environment Name")
        flag.StringVar(&username, "user", "", "Apigee Organization Username")
        flag.StringVar(&password, "pass", "", "Apigee Organization Password")
        flag.StringVar(&key, "key", "", "Microgateway Key")
        flag.StringVar(&scrt, "sec", "", "Microgateway Secret")
        flag.StringVar(&mgmturl, "murl", "", "Apigee Edge Management API Endpoint")
        flag.StringVar(&configFile, "conf", "", "Apigee Microgateway Config File")
        flag.StringVar(&svcFile, "svc", "", "k8s service yaml")
	flag.StringVar(&mgVer, "mgver", "", "Micrgoateway version")
        flag.BoolVar(&infoLogger, "debug", false, "Enable debug mode")

	// Parse commandline parameters
	flag.Parse()

	//check mandatory params
	checkParams(org, env, username, password, configFile)

	if infoLogger {
		Init(os.Stdout, os.Stdout, os.Stderr)
	} else {
		Init(ioutil.Discard, os.Stdout, os.Stderr)
	}

	Info.Println("Reading Microgateway configuration file ", configFile)
	configFileData, fileerr = ioutil.ReadFile(configFile)

        if fileerr != nil {
                Error.Fatalln("Error opening config file:\n%#v\n", fileerr)
                return
        }

	// Get filename
	yamlFilepath, err := filepath.Abs(svcFile)

	// Get reader from file opening
	reader, err := os.Open(yamlFilepath)
	if err != nil {
		panic(err)
	}

	// Split YAML into chunks or k8s resources, respectively
	yamlDecoder := yaml.NewDocumentDecoder(ioutil.NopCloser(reader))

	printSecret(createSecret())
	recurse(yamlDecoder, reader, nil)

}
