Feature: control one openflow switch using learning-switch controller

  As a Trema user
  I want to control one openflow switch using learning-switch controller
  So that I can send and receive packets

  Background:
   Given I cd to "../../src/examples/learning_switch/"

  @slow_process
  Scenario: Run the Ruby example
    Given I run `trema run ./learning-switch.rb -c sample.conf -d`
    And wait until "LearningSwitch" is up
    When I send 1 packet from host1 to host2
    And I run `trema show_stats host1 --tx`
    And I run `trema show_stats host2 --rx`
    Then the output from "trema show_stats host1 --tx" should contain "192.168.0.2,1,192.168.0.1,1,1,50"
    And the output from "trema show_stats host2 --rx" should contain "192.168.0.2,1,192.168.0.1,1,1,50"

  @slow_process
  Scenario: Run the C example
    Given I compile "learning_switch.c" into "learning_switch"
    And I run `trema run ./learning_switch -c sample.conf -d`
    When I send 1 packet from host1 to host2
    And I run `trema show_stats host1 --tx`
    And I run `trema show_stats host2 --rx`
    Then the output from "trema show_stats host1 --tx" should contain "192.168.0.2,1,192.168.0.1,1,1,50"
    And the output from "trema show_stats host2 --rx" should contain "192.168.0.2,1,192.168.0.1,1,1,50"
