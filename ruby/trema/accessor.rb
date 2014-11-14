#
# Copyright (C) 2008-2013 NEC Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

require_relative 'mapping'

module Trema
  #
  # A base class for defining user defined like accessors.
  #
  class Accessor
    # mixin mapping of ofp type to implementation class.
    include Mapping
    USER_DEFINED_TYPES = %w( ip_addr mac match packet_info array string bool )

    class AttributeProperty
      attr_reader :required_attributes, :default_attributes, :alias_attributes

      def initialize
        @required_attributes ||= []
        @default_attributes ||= {}
        @alias_attributes ||= {}
      end
    end

    class << self
      def attributes
        @attributes ||= AttributeProperty.new
      end

      def search(type, sub_key)
        key = "#{ type }_#{ sub_key }"
        retrieve key
      end

      def inherited(klass)
        map_ofp_type klass
        primitive_sizes.each do | each |
          define_accessor_meth :"unsigned_int#{ each }"
          define_method :"check_unsigned_int#{ each }" do | number, name |
            begin
              unless number.send("unsigned_#{ each }bit?")
                fail ArgumentError, "#{ name } must be an unsigned #{ each }-bit integer."
              end
            rescue NoMethodError
              raise TypeError, "#{ name } must be a Number."
            end
          end
        end
        USER_DEFINED_TYPES.each { | meth | define_accessor_meth meth }
      end

      ############################################################################

      private

      ############################################################################

      def primitive_sizes
        (8..64).step(8).select { | i | i.to_s(2).count('1') == 1 }
      end

      def define_accessor_meth(meth)
        class_eval do
          define_singleton_method :"#{ meth }" do | *args |
            attrs = args
            opts = extract_options!(args)
            check_args args
            attrs.delete(opts) unless opts.empty?
            opts.store :attributes, attrs
            opts.store :validate_with, "check_#{ meth }" if meth.to_s[/unsigned_int\d\d/]
            attrs.each do | attr_name |
              define_accessor attr_name, opts
              if opts.key? :alias
                alias_method opts[:alias], attr_name
                attributes.alias_attributes[attr_name] = opts[:alias] if opts.key? :alias
              end
              attributes.required_attributes << attr_name if opts.key? :presence
              attributes.default_attributes[attr_name] = opts[:default] if opts.key? :default
            end
          end
        end
      end

      def define_accessor(attr_name, opts)
        class_eval do
          define_method attr_name do
            instance_variable_get "@#{ attr_name }"
          end

          define_method "#{ attr_name }=" do | v |
            if opts.key? :presence
              if opts[:presence] == true
                if v.nil?
                  fail ArgumentError, "#{ attr_name } is a mandatory option."
                end
              end
            end
            validation_methods = opts.select { | key, _ | key == :within || key == :validate_with }
            validation_methods.each { | _, meth | __send__(meth, v, attr_name) }
            instance_variable_set "@#{ attr_name }", v
          end
        end
      end

      def extract_options!(args)
        if args.last.is_a?(Hash) && args.last.instance_of?(Hash)
          args.pop
        else
          {}
        end
      end

      def check_args(args)
        fail ArgumentError, 'You need at least one attribute' if args.empty?
      end
    end

    def initialize(options = nil)
      setters = self.class.instance_methods.select { | i | i.to_s =~ /[a-z].+=$/ }
      required_attributes = self.class.attributes.required_attributes
      if required_attributes.empty?
        required_attributes = self.class.superclass.attributes.required_attributes
      end

      set_default setters
      case options
      when Hash
        setters.each do | each |
          opt_key = each.to_s.sub('=', '').to_sym
          if options.key? opt_key
            public_send each, options[opt_key]
          elsif options.key? self.class.attributes.alias_attributes[opt_key]
            public_send each, options[self.class.attributes.alias_attributes[opt_key]]
          else
            fail ArgumentError, "Required option #{ opt_key } is missing for #{ self.class.name }" if required_attributes.include? opt_key
          end
        end
      when Integer, String
        unless setters.empty?
          public_send setters[0], options
        else
          fail ArgumentError, "#{ self.class.name } accepts no options"
        end
      else
        fail ArgumentError, "Required option #{ required_attributes.first } missing for #{ self.class.name }" unless required_attributes.empty?
      end
    end

    def set_default(setters)
      default_attributes = self.class.attributes.default_attributes
      setters.each do | each |
        opt_key = each.to_s.sub('=', '').to_sym
        if default_attributes.key? opt_key
          if default_attributes[opt_key].respond_to? :call
            public_send each, default_attributes[opt_key].call
          else
            public_send each, default_attributes[opt_key]
          end
        end
      end
    end
  end
end

### Local variables:
### mode: Ruby
### coding: utf-8-unix
### indent-tabs-mode: nil
### End:
