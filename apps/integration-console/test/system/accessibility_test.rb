require "application_system_test_case"

class AccessibilityTest < ApplicationSystemTestCase
  test "dashboard landmarks and dynamic regions are axe clean" do
    visit root_path

    assert_selector "html[lang='en']", visible: false
    assert_selector "main#main-content"
    assert_selector "[role='log'][aria-live='polite']"
    assert_axe_clean
  end
end
