from pyattck import Attck
import json
from elasticsearch import Elasticsearch
import configuration_file as es_config


es = Elasticsearch(
    [es_config.elasticsearch_config['ELASTICSEARCH_HOSTNAME']],

    # turn on SSL
    use_ssl=es_config.elasticsearch_config['USE_SSL'],
    # make sure we verify SSL certificates
    verify_certs=es_config.elasticsearch_config['VERIFY_CERT'],
    http_auth=(es_config.elasticsearch_config['ELASTICSEARCH_USERNAME'], es_config.elasticsearch_config['ELASTICSEARCH_PASSWORD'])

    # provide a path to CA certs on disk
    #ca_certs='/path/to/CA_certs'
)

attack = Attck()
technique_list = []

#Create index template for mitre data
def create_mitre_template():
    with open('mitre_attck_template.json','r') as f:
      template = f.read()
    # print(template)
    # data = json.load(template)
    create_template = es.indices.put_template(name="mitre_attck_template", body=template)   
    print(create_template)
    # template.close() 



#Get all mitre subtechniques
def get_subtechniques():
    for technique in attack.enterprise.techniques:
        for tactic in technique.tactics:
          for subtechnique in technique.subtechniques:
            event_id = tactic.id + "_" + technique.id + "_" + subtechnique.id
            item = { 
                    "threat" : {
                        "technique" : {
                            "id" : technique.id,
                            "name" : technique.name,
                            "subtechnique" : {
                                "id" : subtechnique.id,
                                "name" : subtechnique.name
                            }
                        },
                        "tactic" : {
                            "id" : tactic.id,
                            "name" : tactic.name
                        },
                        "framework" : "Mitre Att&ck"
                    }
                }
            index_event = es.index(index="mitre_attck", body=item, pipeline="mitre_attck_parsing", id=event_id)
            print("{} event {}".format(index_event['result'], event_id))

#GET all Mitre techniques that do not contain a subtechnique
def get_all_technique_no_sub():
    for tactic in attack.tactics:
        for technique in tactic.techniques:
            if technique.subtechnique == None:
                event_id = tactic.id + "_" + technique.id
                item = { 
                    "threat" : {
                        "technique" : {
                            "id" : technique.id,
                            "name" : technique.name
                        },
                        "tactic" : {
                            "id" : tactic.id,
                            "name" : tactic.name
                        },
                        "framework" : "Mitre Att&ck"
                    }
                }
                
                index_event = es.index(index="mitre_attck", body=item, id=event_id)
                print("{} event {}".format(index_event['result'], event_id))


def main():
    create_mitre_template()
    get_subtechniques()
    get_all_technique_no_sub()
if __name__ == "__main__":
    main()

