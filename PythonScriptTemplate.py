from SiemplifyAction import SiemplifyAction

def main():
	siemplify = SiemplifyAction()
	siemplify.script_name = 'action name'
	siemplify.LOGGER.info("---- Started ----")

	# sample script:
	# configuration = siemplify.get_configuration('Provider')

	# for entity in siemplify.target_entities:
	#     entity.additional_properties['EnrichmentProperty'] = ...
	# siemplify.update_entities(siemplify.target_entities)
	#

	output_message = 'output message'
	result_value = 'true'
	siemplify.end(output_message, result_value)

if __name__ == "__main__":
	main()